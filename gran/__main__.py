import click

from .helper import _test

@click.command()
def main ():
    _test()

if __name__ == "main":
    main()
