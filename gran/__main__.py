import click, logging

from .helper import parse_pem, parse_csr, req, signed_req

ACME_STAG_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_PROD_URL = "https://acme-v02.api.letsencrypt.org/directory"

# Set up logging
log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

@click.command()
@click.option("-k", "--key", required=True, help="account key PEM file")
@click.option("-c", "--csr", required=True, help="CSR file for domain(s)")
# @click.option("-d", "--dir", required=True, help="path for ACME challenges")
def cli (key, csr):
    """drive the whole thing"""
    URL = ACME_STAG_URL

    log.info("Parsing account PEM key...")
    thumbprint, alg, jwk = parse_pem(key)
    # log.info(f"Thumbprint :\n{thumbprint}")

    log.info("Parsing CSR for domains...")
    domains = parse_csr(csr)
    log.info(f"Domains found: {', '.join(domains)}")

    log.info("Requesting directory...")
    directory, _, _ = req(URL, err="error getting directory")

    # TODO: add ability to update contact details (email)?
    log.info("Registering/creating account...")
    tos = {"termsOfServiceAgreed": True}
    account, code, headers = signed_req(directory["newAccount"], tos, "error registering", directory=directory, alg=alg, jwk=jwk, key=key)
    log.info("Registered!" if code == 201 else "Already registered!")
