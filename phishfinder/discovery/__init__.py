"""
# Discovery Module
The discovery module provides submodules which can be used to generate and gather various information
on domains.

It provides the main discovery pipeline for PhishFinder which includes:

1. Domain generation using DNSTwist
2. Domain certificate search for generated domains
3. HTTP and HTTPS services probe on domains found having certificates using HTTProbe
4. Gathering additional information such as ssdeep score, MX services, etc. using DNSTwist components

Further information on this module or pipeline can be found within the submodules' documentation.

This module can be used as a standalone from the PhishFinder package. Each submodule provides
public functions.
"""