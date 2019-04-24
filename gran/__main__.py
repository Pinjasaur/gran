import click, logging

from .helper import parse_pem, parse_csr, req, signed_req, do_challenge

ACME_STAG_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_PROD_URL = "https://acme-v02.api.letsencrypt.org/directory"

# Set up logging
log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

@click.command()
@click.option("-k", "--key", required=True, help="account key PEM file")
@click.option("-c", "--csr", required=True, help="CSR file for domain(s)")
@click.option("-d", "--dir", "dir_", required=True, help="path for ACME challenges")
def cli (key, csr, dir_):
    """drive the whole thing"""
    URL = ACME_STAG_URL

    log.info("Parsing account PEM key...")
    thumbprint, alg, jwk = parse_pem(key)

    log.info("Parsing CSR for domains...")
    domains = parse_csr(csr)
    log.info(f"Domains found: {', '.join(domains)}")

    log.info("Requesting ACME directory...")
    directory, _, _ = req(URL, err="error getting directory")

    # TODO: add ability to update contact details (email)?
    log.info("Registering/creating account...")
    # NOTE: First-time `signed_req` is called, `account_headers` is not passed in
    account, code, account_headers = signed_req(directory["newAccount"], {"termsOfServiceAgreed": True}, "error registering", directory=directory, alg=alg, jwk=jwk, key=key)
    log.info("Registered!" if code == 201 else "Already registered!")

    log.info("Creating a new order...")
    payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = signed_req(directory["newOrder"], payload, "error creating new order", directory=directory, alg=alg, jwk=jwk, key=key, account_headers=account_headers)

    for auth_url in order["authorizations"]:
        authorization, _, _ = req(auth_url, err="error getting challenges")
        domain = authorization['identifier']['value']

        log.info(f"Verifying {domain}...")
        do_challenge(authorization, auth_url, domain, thumbprint=thumbprint, wk_dir=dir_, directory=directory, alg=alg, jwk=jwk, key=key, account_headers=account_headers)
        log.info(f"{domain} verified!")
