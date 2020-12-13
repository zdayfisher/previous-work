"""
Domain certificate search module.

This module provides several functions allowing to retrieve
certificate information for domains from crt.sh.

Purpose
-------
Provide the Discovery pipeline the ability to retrieve certificate
information for the domain names that are generated.

Non-Public Functions
--------------------
.. note:: Non-public functions are not part of this API documentation.
    More information about these functions can be found in the source code
    in the form of docstrings.

- `_issuer_regex`: Extracts certificate issuer's information from a crt.sh result.
- `_search_from_list_of_dictionaries`: Integration function to allow DNSTwist results to
    be directly passed to this module for searches.
"""
from crtsh import crtshAPI as crt
import re
import pandas
from datetime import date, datetime
from tqdm import tqdm


def _issuer_regex(issuer_name_string):
    """
    Returns the certificate issuer's country string and organization name
    string from a crt.sh issuer_name string.
    """

    result = re.findall('(C|O)=("[\w, \.-]+"|[\w\' ]+)', issuer_name_string)

    result = dict(result)
    
    # Assign the value if it exist in the result, else assign empty string
    country = result['C'] if 'C' in result.keys() else ""
    organization = result['O'] if 'O' in result.keys() else ""
    
    return country, organization


def _search_from_list_of_dictionaries(list_of_dict):
    """
    Searches for certificates from a list outputted from a 
    dnstwist domain name generation and returns a dataframe
    with the results.

    Used by as an integration layer between DNSTwist's output
    format (dictionary) and the public search function.
    """
    result_dataframes = []

    for dictionary in tqdm(list_of_dict, desc='Searching for domain certificates', unit='domains'):
        search_result_df = search(
            dictionary['domain-name'],
            dictionary['original-domain'],
            drop_diplicates=False
        )

        search_result_df['fuzzer'] = [dictionary['fuzzer'] for i in range(search_result_df.shape[0])]

        result_dataframes.append(search_result_df)
    
    # Combine all result dataframes
    concat_df = pandas.concat(result_dataframes).drop_duplicates().reset_index(drop=True)

    return concat_df


def search(domain, original_domain='N/A', drop_diplicates=True, include_expired=False):
    """
    Searches crt.sh for a domain's certificates.
    
    Parameters
    ----------
    domain: str
        Domain name including the top-level domain used for the crt.sh query.

    original_domain: str
        Original domain used by DNSTwist's domain generation to generate the
        `domain` parameter. Used to match certificate results to original
        domains in the Discovery pipeline.

    drop_duplicates: bool
        Drop duplicate rows in the results DataFrame if they exist.
        
    include_expired: bool
        If set to true, expired certificates will not be retrieved from crt.sh.
    
    Returns
    -------
    Returns: pandas.DataFrame
        Returns a DataFrame containing original domain (if provided), domain name found
        in a certificate, issuer name, issuer country, certificate start and end, and
        certificate duration in days.
    """
    result_dataframe = pandas.DataFrame(
        columns=[
            'original-domain',
            'domain-name',
            'issuer-name',
            'issuer-country',
            'cert-start',
            'cert-end',
            'cert-duration'
        ]
    )

    result_index = 0

    certs = crt().search(domain, wildcard=True, expired=include_expired)

    if isinstance(certs, type(None)):
        return result_dataframe

    for record in certs:
        issuer_country, issuer_name = _issuer_regex(record['issuer_name'])

        start_date = datetime.strptime(
            record['not_before'], "%Y-%m-%dT%H:%M:%S"
        ).date()

        end_date = datetime.strptime(
            record['not_after'], "%Y-%m-%dT%H:%M:%S"
        ).date()

        name_values = record['name_value'].split('\n')

        for name in name_values:
            if "*" not in name:
                result_dataframe.loc[result_index] = [
                    original_domain,
                    name,
                    issuer_name,
                    issuer_country,
                    start_date,
                    end_date,
                    (end_date - start_date).days
                ]

                result_index += 1

    # Remove duplicates and reset dataframe's index
    if drop_diplicates:
        result_dataframe = result_dataframe.drop_duplicates().reset_index(drop=True)

    return result_dataframe
