"""
Tool's main module.

Purpose
-------
Provides an entry point for the phishfinder command line tool.

Non-Public Functions
--------------------

.. note:: Non-public functions are not part of this API documentation.
    For more information on these functions, click "Expand Source Code"
    below to view the docstrings in the source code.

- `_parse_list_file`: Parses files with lists of items into lists
    of strings.
"""
import argparse
import pandas as pd
from .discovery import discovery
from .evaluation import evaluation

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

    # Exclusion list input argument
    parser.add_argument(
        '-e',
        '--exclude-domains',
        dest='exclusions_path',
        help=(
            'Path to the file containing a list of domains '
            'to exclude from evaluation.'
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
            'Include the list of common top-level domains when '
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

    # Filter out domain names from the exclusion list
    if args.exclusions_path:
        legit_list = _parse_list_file(args.exclusions_path)

        discovery_results = discovery_results[
            ~discovery_results['domain-name'].isin(legit_list)
        ]

    # Run the evaluation module
    evaluation_results = evaluation.evaluation(discovery_results)

    #Print results to a file (if path is provided), or to console
    if args.output_file:
        evaluation_results.to_csv(args.output_file)
    else:
        pd.set_option("display.max_rows", None, "display.max_columns", None)
        print(evaluation_results[['originam-domain', 'domain-name', 'prediction']])




if __name__ == '__main__':
    main()