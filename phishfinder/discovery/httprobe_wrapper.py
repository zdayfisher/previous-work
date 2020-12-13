"""
Wrapper module for the HTTProbe tool.

This module is a wrapper for the HTTProbe tool:
[https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe).

Purpose
-------
Allows the Discovery pipeline to detect running HTTP and 
HTTPs services on a given domain.

Non-Public Functions
--------------------

.. note:: Non-public functions are not part of this API
    documentation. More information about these functions
    can be found in the source code in the functions' docstrings.

- `_create_batch_strings`: Creates a string of domains with less than
    25k characters in length to allow for HTTProbe to be ran without
    argument length issues.
"""

from subprocess import run, Popen, PIPE
import pandas
from subprocess import run, PIPE
from tqdm import tqdm


def _create_batch_strings(domains):
    """
    Creates batch strings of domains.

    Parameters
    ----------
    domains: list
        List of domain names with top-level domain/

    Returns
    -------
    Returns: list of str
        Returns a list of strings not exceeding a length of 25,000
        containing domain names separated by a newline character (\\n)
    
    Description
    -----------
    Takes a list of domains and generates a list of strings
    containing several domains which have a length no greater
    than the system's max argument length.
    """
    batches = []
    current_batch = []
    current_batch_char_length = 0

    argument_limit = int(
        run(
            ['getconf', 'ARG_MAX'],
            stdout=PIPE
        ).stdout.decode('utf-8')
    )

    for domain in tqdm(domains, desc='Creating batches of domains', unit='domains'):
        if len(domain) + current_batch_char_length < 25000:
            current_batch.append(domain)
            current_batch_char_length += len(domain)
        else:
            batches.append(current_batch)
            current_batch_char_length = len(domain)
            current_batch = [domain]
        
    if current_batch:
        batches.append(current_batch)
    
    batch_strings = ['\n'.join(batch) for batch in batches]

    print(f'{len(batch_strings)} batches created.')
    
    return batch_strings


def probe(domains):
    """
    Finds if domains have http or https services running.

    Parameters
    ----------
    domains: list of str
        List of domain names
    
    Returns
    -------
    Return: pandas.DataFrame
        Returns a DataFrame of domain name (string),
        http service running (bool), and https service running (bool).
    """

    input_strings = _create_batch_strings(domains)

    results = []

    # cat temp file and pipe into httprobe
    for input_domains in tqdm(input_strings, desc='Probing domains for http/https services', unit='batch'):
        cat_proc = Popen(['echo', '-e', f'"{input_domains}"'], stdout=PIPE)
        probe_output = run(['httprobe'], stdin=cat_proc.stdout, stdout=PIPE).stdout
        cat_proc.wait()

        stdout_data = probe_output.decode().split('\n')

        # Removes empty string item at the end of the list if it occurs
        if stdout_data[-1] == '':
            stdout_data.pop()
        
        results += stdout_data

    result_dataframe = pandas.DataFrame(
        columns=[
            'domain-name',
            'http-active',
            'https-active'
        ]
    )

    for i, domain in enumerate(domains):
        result_dataframe.loc[i] = [
            domain,
            1 if f'http://{domain}' in results else 0,
            1 if f'https://{domain}' in results else 0
        ]

    return result_dataframe
