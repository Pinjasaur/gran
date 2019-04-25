import click, logging, os

from .helper import parse_pem, parse_csr, req, signed_req, do_challenge, cmd, \
                    b64, req_until_not

ACME_STAG_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_PROD_URL = "https://acme-v02.api.letsencrypt.org/directory"

# Set up logging
log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

@click.command()
@click.option("--key", help="account key PEM file", required=True)
@click.option("--csr", help="CSR file for domain(s)", required=True)
@click.option("--dir", "dir_", help="path for ACME challenges", required=True)
@click.option("--quiet", help="supress non-essential output", is_flag=True)
@click.option("--test", help="use the Let's Encrypt staging API", is_flag=True)
def cli (key, csr, dir_, quiet, test):
    """Get a TLS certificate via (Let's Encrypt) ACME."""
    # Set the correct ACME endpoint
    ACME_URL = ACME_STAG_URL if test else ACME_PROD_URL

    # Ignore info-level logging if `--quiet` is passed
    if quiet:
        log.setLevel(logging.ERROR)

    log.info("Parsing account PEM key...")
    thumbprint, alg, jwk = parse_pem(key)

    log.info("Parsing CSR for domains...")
    domains = parse_csr(csr)
    log.info(f"Domains found: {', '.join(domains)}")

    log.info("Requesting ACME directory...")
    directory, _, _ = req(ACME_URL, err="error getting directory")

    log.info("Registering account with ACME...")
    # NOTE: First-time `signed_req` is called, `account_headers` is not passed
    # in because there has not been registration/confirmation of registration
    account, code, account_headers = signed_req(directory["newAccount"], {"termsOfServiceAgreed": True}, "error registering", directory=directory, alg=alg, jwk=jwk, key=key)
    log.info("Registered!" if code == 201 else "Already registered!")

    log.info("Creating a new order with ACME...")
    payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = signed_req(directory["newOrder"], payload, "error creating new order", directory=directory, alg=alg, jwk=jwk, key=key, account_headers=account_headers)

    for auth_url in order["authorizations"]:
        authorization, _, _ = req(auth_url, err="error getting challenges")
        domain = authorization["identifier"]["value"]

        log.info(f"Creating challenge for {domain}...")
        wk_path = do_challenge(authorization, auth_url, domain, thumbprint=thumbprint, wk_dir=dir_, directory=directory, alg=alg, jwk=jwk, key=key, account_headers=account_headers, log=log)
        log.info(f"{domain} verified!")

    log.info("Signing certificate & finalizing order with ACME...")
    csr_der = cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err="error exporting CSR as DER")
    signed_req(order["finalize"], {"csr": b64(csr_der)}, "error finalizing order", directory=directory, alg=alg, jwk=jwk, key=key, account_headers=account_headers)

    log.info("Polling ACME for order completion...")
    order = req_until_not(order_headers["Location"], ["pending", "processing"], "error checking order status")
    if order["status"] != "valid":
        raise ValueError(f"Order failed: {order}")

    # Clean up challenge
    os.remove(wk_path)
    log.info("Certificate signed, downloading...")
    fullchain, _, _ = req(order["certificate"], err="certificate download failed")
    print(fullchain, end="")
