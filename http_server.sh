#!/usr/bin/env bash

# based on https://xdeb.org/post/2016/02/09/lets-encrypt-my-servers-with-acme-tiny/

cd challenges
python3 -m http.server 80
