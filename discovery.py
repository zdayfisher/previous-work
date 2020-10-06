import numpy as np
from subprocess import Popen, run, PIPE
from os import remove


def dnstwist(whitelist):
    '''
    Returns 2d numpy array of:
        fuzzer, domain-name, dns-a, dns-aaaa, dns-mx, dns-ns, geoip-country, whois-created, ssdeep-score
    '''
    dnstwist_results = []

    for domain in whitelist:
        print(f'Generating possible domains for {domain}...')
        dnstwist_proc = run(
            ['dnstwist',
            '-r', '-w', '-g', '--ssdeep', '-m',
            '-f', 'csv',
            '--tld', './Dictionaries/english.dict',
            '--tld', './Dictionaries/french.dict',
            '--tld', './Dictionaries/common_tlds.dict',
            domain],
            stdout=PIPE
            )

        dnstwist_results.append(
            np.array([line.split(',') for line in dnstwist_proc.stdout.decode().split('\n')[1:]][:-1], dtype=list)
        )

    cleaned_output = np.concatenate(dnstwist_results)
    np.unique(cleaned_output, return_index=True)

    return cleaned_output


def probe(domains):
    print('Probing domains for running http/https services...')

    with open('domains.tmp', 'w') as f:
        for domain in domains:
            f.write(f'{domain}\n')

    # cat temp file and pipe into httprobe    
    cat_proc = Popen(['cat', 'domains.tmp'], stdout=PIPE)
    probe_output = run(['httprobe'], stdin=cat_proc.stdout, stdout=PIPE).stdout
    cat_proc.wait()

    remove(f'domains.tmp')

    clean_domain_list = probe_output.decode().split("\n")

    # Removes empty string item at the end of the list if it occurs
    if clean_domain_list[-1] == '':
        clean_domain_list.pop()
    
    return clean_domain_list


def cert_check(domains):
    raise NotImplementedError


def main(domains):
    dnstwist_results = dnstwist(domains)
    
    probe_results = probe(
        [dnstwist_results[i][1] for i in range(len(dnstwist_results))]
    )

    # Add two columns of zeros, first for http and second for https services
    dnstwist_results = np.c_[dnstwist_results, [0 for i in range(len(dnstwist_results))], [0 for i in range(len(dnstwist_results))]]

    for record in dnstwist_results:
        if f'http://{record[1]}' in probe_results:
            record[-2] = 1
        
        if f'https://{record[1]}' in probe_results:
            record[-1] = 1
    
    return dnstwist_results


if __name__ == "__main__":
    main(['bell.ca', 'support.bell.ca'])
