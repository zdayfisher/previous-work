from .dnstwist_wrapper import dnstwist
from .httprobe_wrapper import probe
from . import cert_search
import pandas


def discover(domains, keywords = []):
    '''
    Discover possible fishing domains based on a given list of whitelisted
    domain names and a list of keywords.

    domains: list of domain names. E.g. ['netflix.com', 'paypal.com']

    keywords: list of keywords used to generate possible fishing domains.
    E.g. ['support', 'login']

    returns a pandas DataFrame with information found about each generated
    possible fishing domain.
    '''
    dnstwist_results = dnstwist(domains, keywords)

    # Probe for running http/https services on domains from dnstwist
    probe_results = probe(
        list(dnstwist_results['domain-name'])
    )

    data = dnstwist_results.merge(probe_results, on='domain-name', how='left')

    # Ger certficates of domains similar to provided domains
    certs = cert_search.search(list(data['domain-name']))

    return data, certs


if __name__ == "__main__":
    data, certs = discover(['netflix.com'], ['support', 'help', 'login'])
