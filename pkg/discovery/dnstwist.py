import pandas
from subprocess import run, PIPE
from io import StringIO


def dnstwist(whitelist):
    '''
    Generates possible phishing domain names based on the
    provided whitelist and verifies IP's, geolocations,
    name service, site similarity to the original domain, etc.

    Returns a DataFrame of:
        fuzzer, domain-name, dns-a, dns-aaaa, dns-mx,
        dns-ns, geoip-country, whois-created, ssdeep-score
    '''
    dnstwist_result_pandas = []

    for domain in whitelist:
        print(f'Generating possible domains for {domain}...')
        dnstwist_proc = run(
            [
                'dnstwist',
                '-r', '-w', '-g', '--ssdeep', '-m',
                '-f', 'csv',
                '--tld', './tld/english.dict',
                '--tld', './tld/french.dict',
                '--tld', './tld/common_tlds.dict',
                domain
            ],
            stdout=PIPE
        )

        decoded_stdout = dnstwist_proc.stdout.decode()

        stdout_data = StringIO(decoded_stdout)

        dnstwist_result_pandas.append(
            pandas.read_csv(stdout_data, sep=',')
        )

    # Combine pandas from each domain and remove duplicates.
    unique_result_dataframe = pandas.concat(dnstwist_result_pandas)\
                                    .drop_duplicates()\
                                    .reset_index(drop=True)

    return unique_result_dataframe
