"""
Main domain discovery module.

This module provides the discover function which acts as a pipeline for
the discovery module.

Purpose
-------
Generate domain names and gather various informations relating to them
including certificates, the presence of HTTP and HTTPS services, and 
similarities between the original domain's webpage and the generated
domains.
"""
from .httprobe_wrapper import probe
from . import cert_search
from . import dnstwist_wrapper
import pandas


def discover(domains, keywords = [], french_tld=False, english_tld=False, common_tld=False):
    """
    Discovers possible phishing domains based on a given list of whitelisted
    domain names and a list of keywords.

    .. warning:: Each domain provided in the `domains` parameter list can generate thousands of fuzzied domains.
        Using a large number of domains in this parameter can drastically increase the runtime of the pipeline as
        each fuzzied domain will be processed (certificate search, HTTP/HTTPS probe, etc.).

        *It is not recommended to use a large number of domains for this parameter at one time.*

    Parameters
    ----------
    domains: list
        List of domain names. E.g. ['netflix.com', 'paypal.com']

    keywords: list
        List of keywords used to generate possible phishing domains.
        E.g. ['support', 'login']

    french_tld: bool
        Include the top-level domains from the French TLD list.
    
    english_tld: bool
        Include the top-level domains from the English TLD list.
    
    common_tld: bool
        Include the most common top-level domains.

    Returns
    -------
    Returns: pandas.DataFrame
        Returns a pandas DataFrame with information found about each generated
        possible phishing domain.
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
