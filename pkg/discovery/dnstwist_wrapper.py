import pandas
import queue
import dnstwist as dnstwist_module
import ssdeep

from subprocess import run, PIPE
from io import StringIO
from os import path, remove
from tqdm import tqdm
from os.path import dirname, join as pjoin

DNSTWIST_USER_AGENT = 'Mozilla/5.0 dnstwist/20201022'

def _parse_tld_file(filename):
    """
    Gets the contents of a top-level domain (TLD) dictionary file
    and returns a list of its TLDs.
    """

    with open(pjoin(dirname(__file__), f'tld/{filename}'), 'r') as f:
        file_content = f.read()

    # Removes comments found within the 
    return [tld for tld in file_content.split('\n') if tld.isalpha()]


def _create_csv(domains):
    """
    Creates a csv string from the list of dictionaries containing 
    domain information.
    """
    keys = [
        'original-domain',
        'domain-name',
        'issuer-name',
        'issuer-country',
        'cert-start',
        'cert-end',
        'cert-duration',
        'fuzzer',
        'http-active',
        'https-active',
        'dns-ns',
        'dns-a',
        'dns-mx',
        'geoip-country',
        'banner-http',
        'ssdeep-score',
        'whois-created',
        'whois-registrar'
    ]

    if domains:
        csv = [','.join(keys)]
    else:
        csv = ''

    for domain in domains:
        domain_row = []
        for key in keys:
            if isinstance(domain[key], list):
                domain_row.append(
                    ';'.join(domain.get(key, []))
                )
            else:
                domain_row.append(str(domain.get(key, '')).replace(',', ''))
        
        csv.append(
            ','.join(domain_row)
        )

    return '\n'.join(csv)


def dnstwist(whitelist, keywords = [], french_tld=False, english_tld=False, common_tld=False):
    """
    Generates possible phishing domain names based on the
    provided whitelist and keywords.

    Returns a list of generated domains
    """

    # Use abused TLDs by default
    tld_list = _parse_tld_file('abused_tlds.dict')

    if french_tld:
        tld_list += _parse_tld_file('french.dict')

    if english_tld:
        tld_list += _parse_tld_file('english.dict')
    
    if common_tld:
        tld_list += _parse_tld_file('common_tlds.dict')

    dnstwist_domains = []

    for domain in tqdm(whitelist, desc='Fuzzing domains', unit='domains'):
        url = dnstwist_module.UrlParser(domain)

        fuzzer = dnstwist_module.DomainFuzz(
            url.domain, dictionary=keywords, tld_dictionary=tld_list
        )
        
        fuzzer.generate()

        # Add original domain to dictionaries
        for result in fuzzer.domains:
            result['original-domain'] = domain
        
        dnstwist_domains += fuzzer.domains

    return dnstwist_domains


def process_existing_domains(original_domain, domains=[], thread_count=10):
    """
    Modified code from dnstwist.main
    (https://github.com/elceef/dnstwist/blob/master/dnstwist.py)
    which processes domains through ssdeep, whois, mx verification,
    and geoip verification.

    original_domain must be the string of the domain used to generate the
    fuzzied domains.

    domains must be a list of dictionaries of format
    {'fuzzer': 'value', 'domain-name': 'domain'}. This is a requirment for
    dnstwist compatability.
    """
    def _exit(code):
        print(dnstwist_module.FG_RST + dnstwist_module.ST_RST, end='')
        dnstwist_module.sys.exit(code)

    threads = []
    include_ssdeep = True

    def p_cli(text):
        print(text, end='', flush=True)
    def p_err(text):
        print(str(text), file=dnstwist_module.sys.stderr, flush=True)

    def signal_handler(signal, frame):
        print('\nStopping threads... ', file=dnstwist_module.sys.stderr, end='', flush=True)
        for worker in threads:
            worker.stop()
            worker.join()
        print('Done', file=dnstwist_module.sys.stderr)
        _exit(0)

    dnstwist_module.signal.signal(dnstwist_module.signal.SIGINT, signal_handler)
    dnstwist_module.signal.signal(dnstwist_module.signal.SIGTERM, signal_handler)

    # SSDEEP
    try:
        url = dnstwist_module.UrlParser(original_domain)
    except ValueError:
        dnstwist_module.parser.error('invalid domain name: ' + original_domain)

    ssdeep_init = str()
    ssdeep_effective_url = str()

    request_url = url.full_uri()
    p_cli('Fetching content from: %s ' % request_url)
    try:
        req = dnstwist_module.requests.get(
            request_url,
            timeout=dnstwist_module.REQUEST_TIMEOUT_HTTP,
            headers={'User-Agent': DNSTWIST_USER_AGENT}
        )
    except dnstwist_module.requests.exceptions.ConnectionError:
        p_cli('Connection error\n')
        _exit(1)
    except dnstwist_module.requests.exceptions.HTTPError:
        p_cli('Invalid HTTP response\n')
        _exit(1)
    except dnstwist_module.requests.exceptions.Timeout:
        p_cli('Timeout (%d seconds)\n' % dnstwist_module.REQUEST_TIMEOUT_HTTP)
        _exit(1)
    except Exception:
        p_cli('Failed!\n')
        _exit(1)
    else:
        if len(req.history) > 1:
            p_cli('➔ %s ' % req.url.split('?')[0])
        p_cli('%d %s (%.1f Kbytes)\n' % (req.status_code, req.reason, float(len(req.text))/1000))
        if req.status_code // 100 == 2:
            ssdeep_init = ssdeep.hash(''.join(req.text.split()).lower())
            ssdeep_effective_url = req.url.split('?')[0]
        else:
            include_ssdeep = False

    p_cli('Processing %d permutations ' % len(domains))

    jobs = queue.Queue()

    for i in range(len(domains)):
        jobs.put(domains[i])

    for _ in range(thread_count):
        worker = dnstwist_module.DomainThread(jobs)
        worker.setDaemon(True)

        worker.uri_scheme = url.scheme
        worker.uri_path = url.path
        worker.uri_query = url.query

        worker.domain_init = url.domain

        worker.option_extdns = True
        worker.option_geoip = True
        worker.option_banners = True
        worker.option_ssdeep = include_ssdeep
        worker.ssdeep_init = ssdeep_init
        worker.ssdeep_effective_url = ssdeep_effective_url
        worker.option_mxcheck = True
        worker.nameservers = []
        worker.useragent = DNSTWIST_USER_AGENT

        worker.debug = False

        worker.start()
        threads.append(worker)

    qperc = 0
    while not jobs.empty():
        p_cli('·')
        qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
        if qcurr - 20 >= qperc:
            qperc = qcurr
            p_cli('%u%%' % qperc)
        dnstwist_module.time.sleep(1.0)

    for worker in threads:
        worker.stop()
        worker.join()

    p_cli(' %d hits\n' % sum([1 for x in domains if len(x) > 2]))

    domains[:] = [x for x in domains if len(x) > 2]

    p_cli('Querying WHOIS servers ')
    for domain in domains:
        if len(domain) > 2:
            p_cli('·')
            try:
                whoisq = dnstwist_module.whois.query(domain['domain-name'])
            except Exception as e:
                pass
            else:
                if whoisq and whoisq.creation_date:
                    domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
                if whoisq and whoisq.registrar:
                    domain['whois-registrar'] = str(whoisq.registrar)
    p_cli(' Done\n')

    p_cli('\n')

    for i in range(len(domains)):
        for k in ['dns-ns', 'dns-a', 'dns-aaaa', 'dns-mx']:
            if k in domains[i]:
                domains[i][k] = domains[i][k][:1]

    
    csv_data = StringIO(
        _create_csv(domains)
    )

    return pandas.read_csv(csv_data, sep=',')
