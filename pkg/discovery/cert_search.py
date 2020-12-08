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
    """
    result_dataframes = []

    for dictionary in tqdm(list_of_dict, desc='Searching for domain certificates', unit='domains'):
        search_result_df = search(
            dictionary['domain-name'], dictionary['original-domain']
        )

        search_result_df['fuzzer'] = [dictionary['fuzzer'] for i in range(search_result_df.shape[0])]

        result_dataframes.append(search_result_df)
    
    # Combine all result dataframes
    concat_df = pandas.concat(result_dataframes).reset_index(drop=True)

    return concat_df


def search(domain, original_domain=''):
    """
    Searches crt.sh for active certificates that exist for the provided
    domain and returns a DataFrame with certificate information.
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

    certs = crt().search(domain, wildcard=True, expired=False)

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
    result_dataframe = result_dataframe.drop_duplicates().reset_index(drop=True)

    return result_dataframe
