from subprocess import run, Popen, PIPE
import pandas


def probe(domains):
    """
    Finds if domains have http or https services running.

    Returns a DataFrame of domain name (string),
    http service running (bool), and https service running (bool).
    """
    print('Probing domains for running http/https services...')

    input_domains = "\n".join(domains)

    # cat temp file and pipe into httprobe
    cat_proc = Popen(['echo', '-e', input_domains], stdout=PIPE)
    probe_output = run(['httprobe'], stdin=cat_proc.stdout, stdout=PIPE).stdout
    cat_proc.wait()

    stdout_data = probe_output.decode().split("\n")

    # Removes empty string item at the end of the list if it occurs
    if stdout_data[-1] == '':
        stdout_data.pop()

    result_dataframe = pandas.DataFrame(
        columns=['domain-name', 'http-active', 'https-active']
    )

    for i, domain in enumerate(domains):
        result_dataframe.loc[i] = [
            domain,
            f'http://{domain}' in stdout_data,
            f'https://{domain}' in stdout_data
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