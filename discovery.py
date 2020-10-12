from dnstwist import dnstwist
from httprobe import probe

import pandas

def main(domains):
    
    dnstwist_results = dnstwist(domains)
    
    # Extract domains from dnstwist results and probe for running http/https services
    probe_results = probe(
        [panda_row['domain-name'] for panda_row in dnstwist_results.iloc]
    )

    data = dnstwist_results.merge(probe_results, on='domain-name', how='left')

    return data

if __name__ == "__main__":
    main(['bell.ca', 'support.bell.ca', 'virginmobile.com'])
