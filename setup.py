from setuptools import setup, find_packages
from subprocess import run, PIPE

setup(
    name='phishfinder',
    packages=find_packages(),
    version='0.1.0',
    zip_safe=False,
    entry_points={
        'console_scripts': [
                'phishfinder = phishfinder.phishfinder:main'
            ]
    },
    install_requires=[
        'pandas',
        'dnstwist',
        'tqdm',
        'numpy',
        'tldextract',
        'scikit-learn',
        'DNSPython',
        'whois'
    ],
    include_package_data=True
)