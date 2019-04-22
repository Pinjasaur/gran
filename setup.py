from setuptools import setup

setup(
    name = 'gran',
    version = '0.1.0',
    description = 'bite-sized ACME client (for Let\'s Encrypt)',
    author = 'Paul Esch-Laurent',
    packages = ['gran'],
    entry_points = {
        'console_scripts': [
            'gran = gran.__main__:cli'
        ]
    },
    install_requires = ['click']
)
