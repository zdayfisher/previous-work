"""
Main module providing an entry point for the phishfinder 
command line tool.
"""
import argparse
from .discovery import discovery

def _parse_list_file(path):
    """
    Parses files with lists of items into a list of strings.

    Files should contain one item per line.
    """
    with open(path, 'r') as f:
        items = [i for i in f.read().split('\n') if i != '']
    
    return items


def main():
    """
    Tool entry point.

    This function is called when running `phishfinder` in the
    command line.

    Purpose
    -------
    Provide an entry point for the `phishfinder` tool, provide
    argument handingling and running the discovery and evaluation
    modules.
    """
    parser = argparse.ArgumentParser(
        description=(
            'Discovers phishing websites by generating '
            'domains names and evaluating whether or '
            'not they are phishing domains.'
        )
    )

    # Domain list input argument    
    parser.add_argument(
        'domain_list_path',
        help=(
            'Path to the file containing a list of domains. '
            'File should contain one domain per line.'
        ),
        type=str,
    )

    # Keyword list input argument
    parser.add_argument(
        '-k',
        '--keywords',
        dest='keywords_path',
        help=(
            'Path to the file containing a list of keywords. '
            'File should contain one domain per line.'
        ),
        type=str,
        default=None
    )

    # Option to use the French TLD list
    parser.add_argument(
        '--tld-fr',
        dest='french_tld',
        help=(
            'Include the list of French top-level domains when generating '
            'possible phishing domains.'
        ),
        action='store_true'
    )

    # Option to use the English TLD list
    parser.add_argument(
        '--tld-en',
        dest='english_tld',
        help=(
            'Include the list of English top-level domains when generating '
            'possible phishing domains.'
        ),
        action='store_true'
    )

    # Option to use the abused TLD list
    parser.add_argument(
        '--tld-common',
        dest='common_tld',
        help=(
            'Include the list of commonly abused top-level domains when '
            'generating possible phishing domains.'
        ),
        action='store_true'
    )

    # Output file
    parser.add_argument(
        '-o',
        '--output',
        dest='output_file',
        help=(
            'Path of the output file. If none is provided, program outputs to console.'
        )
    )

    # Output format
    parser.add_argument(
        '-f',
        '--format',
        type=str,
        choices=['csv', 'cli'], default='cli'
    )

    args = parser.parse_args()

    domains = _parse_list_file(args.domain_list_path)

    keywords = []
    if args.keywords_path:
        keywords = _parse_list_file(args.keywords_path)

    # Run the discovery pipeline
    discovery_results = discovery.discover(
        domains,
        keywords,
        args.french_tld,
        args.english_tld,
        args.common_tld
    )

    # TODO: filter out domain names listed in a whitelist

    # TODO: Run the evaluation module

    # TODO: Print results to console, to file, etc. according to
    #       Options selected by user.


if __name__ == '__main__':
    main()