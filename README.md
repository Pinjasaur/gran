<h1 align="center">
  <img src=".github/logo.png" alt="gran">
</h1>

[![forthebadge](https://forthebadge.com/images/badges/built-with-grammas-recipe.svg)](https://forthebadge.com)

A bite-sized ACME client for Let's Encrypt.

Boulder -> Pebble -> Gran(ule) -> Grandma -> Grandma's Cookies :cookie:

## Features

This is a barebones ACME client created for my Network Security course. The name
of the game is to get more better at Python 3 and KISS while doing it. Only
HTTP-01 challenges are used, so no wildcard certificates (those require the
DNS-challenges). Heavily inspired by other projects such as acme-tiny, I suspect
there will be a lot of parallels between other minimal ACME clients.

## Install

Developed using Python 3 & pip3 on a macOS environment.

Locally, running `pip3 install -e .` should get you up and running with the
`gran` command available. The only dependency is `click` to make the CLI
experience pretty slick.

## Should I Use This?

Probably not. Here's a non-exhasutive list of probably better options:
- https://github.com/nuxi/acme-tiny (DNS challenge)
- https://github.com/diafygi/acme-tiny (HTTP challenge)
- https://github.com/lukas2511/dehydrated
- https://github.com/RalfJung/lets-encrypt-tiny

## License

[MIT](https://pinjasaur.mit-license.org/@2019).
