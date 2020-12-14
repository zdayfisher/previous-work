"""
# PhishFinder
PhishFinder is a command line tool which allows an individual
or company to detect zero-day phishing websites attempting to
compromise their customers and clients.

## Installation
Since the tool was designed to run on a Linux environment
with specific third-party tools (such as HTTProbe) that require
system configuration, it is recommended to utilize the provided
Dockerfile to create the Docker Image.

### Docker Image
The Docker image is constructed on top of the `debian:stable-slim`
image. Python 3, Golang 1.15.5, and HTTProbe are installed on top
of the Debian base image as dependencies for PhishFinder. PhishFinder
is then installed as a regular Python package inside the Docker image.

### Building the Image
To build the image, simply run the following command from the repository's
root directory: `sudo docker build --network=host -t phishfinder:1.0 .`

.. note:: The build process may take several minutes as Python 3.8.5 must be built before being installed.


## Usage
Basic usage:
`sudo docker run -v [/path/to/input/files/directory]:/ phishfinder:1.0 [options] [domain input filename]`

### Example
To run the tool using a domain file called `domain_list.txt` and keywords file called `keywords_list.txt`
in the /home/user1/Documents directory, and use the English Top-Level Domain list, the following command would be used:

`sudo docker run -v /home/user1/Documents/:/ phishfinder:1.0 --tld-en -k keyword_list.txt domain_list.txt`

## Important Notes
1. Each domain in the list of domains can generate thousands of possible phishing domains. It is not
recommended that an extensive list be provided as the runtime could reach several days in duration.

# Discovery Module
The discovery module provides a set of submodules which can be used to generate and gather various information
on domains. Further information on this module can be found within the module's documentation.

# Evaluation Module
The evaluation module provides PhishFinder with the ability to evaluate the information gathered by the discovery module
and determine whether the domains are legitimate or malicious (phishing). More information on this module can be found within
the module's documentation.
"""