from subprocess import run, Popen, PIPE
import pandas

def probe(domains):
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

    result_dataframe = pandas.DataFrame(columns=['domain-name', 'http-active', 'https-active'])

    for i, domain in enumerate(domains):
        result_dataframe.loc[i] = [
            domain,
            int(f'http://{domain}' in stdout_data),
            int(f'https://{domain}' in stdout_data)
            ]
    
    return result_dataframe
