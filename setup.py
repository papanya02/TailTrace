from setuptools import setup, find_packages

setup(
    name="tailtrace",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'scapy', 
        'argparse',
    ],
    entry_points={
        'console_scripts': [
            'tailtrace=tailtrace.traffic_sniffer:main',  
        ],
    },
)