"""
# PhishFinder
PhishFinder is a command line tool which allows an individual
or company to detect zero-day phishing websites attempting to
compromise their customers and clients.

## Installation
Since the tool was designed to run on a Linux environment
with specific third-party tools (such as HTTProbe) that require
system configuration, it is recommended to utilize the provided
Dockerfile to create a Docker Image.

### Docker Image
The Docker image is constructed on top of the `debian:stable-slim`
image. Python 3, Golang 1.15.5, and HTTProbe are installed on top
of the Debian base image as dependencies for PhishFinder. PhishFinder
is then installed as a Python package inside the Docker image.

### Building the Image
To build the image, simply run the following command from the repository's
root directory: `docker build --network=host -t phishfinder:1.0 .`

.. note:: The build process may take several minutes as Python 3.8.5 must be built from its source before being installed.


## Usage
### Basic Usage
`docker run -v [/path/to/input_output/files/directory]:/io phishfinder:1.0 [options] io/[domain input file]`

All list files (domain inputs, keywords, exclusion list) should be have a single list item per line. These files are parsed
line by line.

### Advanced Usage
PhishFinder provides several options to customize the generation of domains. These options include
additional top-level domain lists that can be used in addition to the most commonly abused top-level domain lists
during domain generation, exclusion lists for domains that should not be evaluated, and keyword lists to generate additional domains.
For a detailed list of options, run `docker run phishfinder:1.0 -h`.

### Example
To run the tool using a domain file called `domain_list.txt` and keywords file called `keywords_list.txt`
located in the `/home/user1/Documents directory`, and use the English Top-Level Domain list, the following command would be used:

`docker run -v /home/user1/Documents:/io phishfinder:1.0 --tld-en -k io/keyword_list.txt io/domain_list.txt`

.. important:: Each domain in the list of input domains can generate thousands of possible phishing domains.
    It is not recommended that an extensive list be provided as the runtime could reach several days in duration.

# Discovery Module
The discovery module provides a set of submodules which can be used to generate and gather various information
on domains. Further information on this module can be found within the module's documentation.

# Evaluation Module
The evaluation module provides PhishFinder with the ability to evaluate the information gathered by the discovery module
and determine whether the domains are legitimate or malicious (phishing). More information on this module can be found within
the module's documentation.
"""