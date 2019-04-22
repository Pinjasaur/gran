import click

from .helper import _test

@click.command()
def cli ():
    _test()
