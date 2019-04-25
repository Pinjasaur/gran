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

## Process

This automates some of the nitty-gritty parts of issuing a TLS certificate from
the days of yesteryear(s). You'll still need to run a few `openssl` commands,
but `gran` does a good chunk of the heavy lifting -- particularly parsing and
exporting.

The mile-high overview:

1. You provide an account (private) key, CSR, and directory for the challenges
   (text files verified by Let's Encrypt).
2. The account key and CSR get parsed.
3. The ACME directory is requested (provides all the endpoints we'll be using).
4. An account is created (or already confirmed to be registered).
5. A new order (with all the domains from the CSR) is created.
6. Challenges are created & ACME is informed that they're live.
7. After they're all verified, the order is finalized.
8. Once the order is complete, the certificate is downloaded.

## Install

Developed using Python 3 & pip3 on a macOS environment.

Locally, running `pip3 install -e .` should get you up and running with the
`gran` command available. The only dependency is `click` to make the CLI
experience pretty slick. You'll also need the `openssl` binary locally.

## Usage

You'll need to supply 3-4 _ish_ things:

1. An account (private) key in PEM format:

    ```
    openssl genrsa 4096 > acct.pem
    ```

    and a key for each domain / CSR:

    ```
    openssl genrsa 4096 > {{domain}}.pem
    ```

2. A CSR:

    ```
    openssl req -new -sha256 -key {{domain}}.pem -subj "/CN={{domain}}" > {{domain}}.csr
    ```

3. A _directory_ to put all the ACME challenges:

    ```
    mkdir -p /var/www/challenges
    ```

    which will need to be configured in your web server to serve the requests
    `http://{{domain}}/.well-known/acme-challenge/{{challenge}}` from the
    directory you provide. Here's a snippet for Nginx:

    ```
    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }
    ```

After that, you can use `gran` like so:

```
gran --key acct.pem --csr {{domain}}.csr --dir /var/www/challenges > fullchain.pem
```

which will provide you with the certificate.

## Should I Use This?

Probably not. Here's a non-exhasutive list of probably better options:
- https://github.com/nuxi/acme-tiny (DNS challenge)
- https://github.com/diafygi/acme-tiny (HTTP challenge)
- https://github.com/lukas2511/dehydrated
- https://github.com/RalfJung/lets-encrypt-tiny

## License

[MIT](https://pinjasaur.mit-license.org/@2019).
