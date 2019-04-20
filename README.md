# gran

A bite-sized ACME client for Let's Encrypt.

Boulder -> Pebble -> Gran(ule) -> Grandma -> Grandma's Cookies

## Features

This is a barebones ACME client created for my Network Security course. The name
of the game is to get more better at Python 3 and KISS while doing it. Only
HTTP-01 challenges are used, so no wildcard certificates (those require the
DNS-challenges). Heavily inspired by other projects such as acme-tiny, I suspeck
there will be a lot of parallels between other minimal ACME clients.

## Install

Developed using Python 3 & pip3 on a macOS environment.

Locally, running `pip install -e .` should get you up and running with the
`gran` command available. The only dependency is `click` to make the CLI
experience pretty slick.

## License

[MIT](https://pinjasaur.mit-license.org/@2019).
