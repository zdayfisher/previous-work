from subprocess import run, Popen, PIPE
import pandas
from subprocess import run, PIPE
from tqdm import tqdm


def _create_batch_strings(domains):
    """
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


def generate_URL_from_results(probe_results_dataframe):
    """
    Generates URL strings from the pandas dataframe with http/https
    if the service is active according to httprobe.

    Returns a list of URLs.
    """
    urls = []

    for i in range(len(probe_results_dataframe)):
        domain = probe_results_dataframe.loc[i]['domain-name']

        if probe_results_dataframe.loc[i]['http-active']:
            urls.append('http://' + domain)
        
        if probe_results_dataframe.loc[i]['https-active']:
            urls.append('https://' + domain)
    
    return urls