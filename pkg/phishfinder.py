import argparse

def main():
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
            'File should contain one domain per line. '
        ),
        type=str,
    )

    # Keyword list input argument
    parser.add_argument(
        '-k',
        '--keywords',
        dest='keywords_path',
        help=(
            'Path to the file containing a list of keyword. '
            'File should contain one keyword per line.'
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
        '--tld-abused',
        dest='french_tld',
        help=(
            'Include the list of commonly abused top-level domains when '
            'generating possible phishing domains.'
        ),
        action='store_true'
    )

    # Output format
    parser.add_argument(
        '-o',
        '--output',
        dest='output_file',
        help=(
            'Path of the output file. If none is provided, program outputs to console.'
        )
    )

    args = parser.parse_args()






if __name__ == '__main__':
    main()