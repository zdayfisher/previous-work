from crtsh import crtshAPI as crt
import re
import pandas
from datetime import date, datetime


def _issuer_regex(issuer_name_string):
    """
    Returns the certificate issuer's country string and organization name
    string from a crt.sh issuer_name string.
    """

    result = re.findall('(C|O)=("[\w, \.-]+"|[\w\' ]+)', issuer_name_string)

    return result[0][1], result[1][1]


def search(domains):
    """
    Searches crt.sh for active certificates that exist for the provided
    list of domains and returns a DataFrame with certificate information.
    """

    result_dataframe = pandas.DataFrame(
        columns=[
            'domain-name',
            'common-name',
            'issuer-name',
            'issuer-country',
            'cert-start',
            'cert-end',
            'cert-duration'
        ]
    )

    result_index = 0

    for domain in domains:
        certs = crt().search(domain, wildcard=False, expired=False)

        if isinstance(certs, type(None)):
            continue

        for record in certs:
            issuer_country, issuer_name = _issuer_regex(record['issuer_name'])

            start_date = datetime.strptime(
                record['not_before'], "%Y-%m-%dT%H:%M:%S"
            ).date()

            end_date = datetime.strptime(
                record['not_after'], "%Y-%m-%dT%H:%M:%S"
            ).date()

            result_dataframe.loc[result_index] = [
                domain,
                record['common_name'],
                issuer_name,
                issuer_country,
                start_date,
                end_date,
                (end_date - start_date).days
            ]

            result_index += 1

    return result_dataframe
