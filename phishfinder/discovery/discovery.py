from .httprobe_wrapper import probe
from . import cert_search
from . import dnstwist_wrapper
import pandas


def discover(domains, keywords = [], french_tld=False, english_tld=False, common_tld=False):
    """
    Discover possible fishing domains based on a given list of whitelisted
    domain names and a list of keywords.

    domains: list of domain names. E.g. ['netflix.com', 'paypal.com']

    keywords: list of keywords used to generate possible fishing domains.
    E.g. ['support', 'login']

    returns a pandas DataFrame with information found about each generated
    possible fishing domain.
    """

    # Fuzz domains based on the domain list, keyword list, and TLD specifications provided
    dnstwist_generation_results = dnstwist_wrapper.dnstwist(
        domains,
        keywords,
        french_tld=french_tld,
        english_tld=english_tld,
        common_tld=common_tld
    )

    # Get certficate information of domains similar to provided domains
    certs_df = cert_search._search_from_list_of_dictionaries(
        dnstwist_generation_results
    )

    # Probe for running http/https services on domains from dnstwist
    probe_results = probe(
        list(certs_df['domain-name'])
    )

    # Combine results from certificate search and http/https probe searches
    data = certs_df.join(probe_results.drop(columns=['domain-name']), how='left')

    # Verify obtain ssdeep scores, geoip info, whois info, MX info, etc.
    dnstwist_data_results = []
    for domain in list(set(data['original-domain'])):
        dnstwist_data_results.append(
            dnstwist_wrapper.process_existing_domains(
                domain,
                data.loc[data['original-domain'] == domain].to_dict('records')
            )
        )

    data = pandas.concat(dnstwist_data_results).reset_index(drop=True)

    return data


if __name__ == "__main__":
    data = discover(['netflix.com'], ['support', 'help', 'login'])
