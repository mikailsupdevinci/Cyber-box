from setuptools import setup, find_packages

setup(
    name='intrusion_toolbox',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'python-nmap',
        'scapy',
        'requests',
        'beautifulsoup4',
        'matplotlib',
        'pandas',
        'openpyxl',
    ],
    entry_points={
        'console_scripts': [
            'intrusion_toolbox=toolbox.main:main',
            'intrusion_toolbox_gui=toolbox.gui:main',
        ],
    },
)
