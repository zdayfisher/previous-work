from setuptools import setup, find_packages
from subprocess import run, PIPE

setup(
    name='pkg',
    packages=find_packages(),
    version='0.1.0',
    zip_safe=False,
    #entry_points={
    #    'console_scripts': [
    #            'pkgdiscovery = pkg.discovery:main'
    #        ]
    #},
    install_requires=[
        'pandas',
        'crtsh',
        'dnstwist'
    ],
    include_package_data=True
)