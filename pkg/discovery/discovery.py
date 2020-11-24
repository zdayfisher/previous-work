from .dnstwist_wrapper import dnstwist
from .httprobe_wrapper import probe
from . import cert_search
import pandas


def discover(domains):

    dnstwist_results = dnstwist(domains)

    # Probe for running http/https services on domains from dnstwist
    probe_results = probe(
        list(dnstwist_results['domain-name'])
    )

    data = dnstwist_results.merge(probe_results, on='domain-name', how='left')

    certs = cert_search.search(list(data['domain-name']))

    return data, certs


if __name__ == "__main__":
    data, certs = discover(['bell.ca', 'support.bell.ca', 'virginmobile.com'])
