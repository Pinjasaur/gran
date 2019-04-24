import base64, binascii, subprocess, time, re, hashlib, json
from urllib.request import urlopen, Request

def b64 (s):
    """base64 encode per the JOSE spec (URL safe, no '=')"""
    return base64.urlsafe_b64encode(s).decode("utf-8").replace("=", "")

def unhex (s, enc="utf-8"):
    """convert hex to bin"""
    return binascii.unhexlify(s.encode(enc))

def exec (cmds, stdin=None, cmd_input=None, err="exec error"):
    """exec a local (external) CLI command"""
    proc = subprocess.Popen(cmds, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(cmd_input)

    if proc.returncode != 0:
        raise IOError(f"{err}\n{stderr}")
    return stdout

def req (url, data=None, err="req error", depth=0):
    """general-purpose request & auto-parse the (JSON) response"""
    try:
        resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "gran-acme-client"}))
        res, code, headers = resp.read().decode("utf-8"), resp.getcode(), resp.headers
    except IOError as e:
        res = e.read().decode("utf-8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}

    # Try & parse JSON
    try:
        res = json.loads(res)
    except ValueError:
        pass

    # Check for badNonce error (allow up to 100 retries)
    if depth < 100 and code == 400 and res["type"] == "urn:ietf:params:acme:error:badNonce":
        raise IndexError(res)

    # No bueno HTTP codes
    if code not in [200, 201, 204]:
        raise ValueError(f"{err}:\nURL: {url}\nData: {data}\nCode: {code}\nResponse: {res}")

    return res, code, headers

def signed_req (url, payload, err, depth=0, headers=None, directory=None, alg=None, jwk=None, key=None):
    """send signed (authenticated) requests to the ACME server"""
    payload64 = b64(json.dumps(payload).encode("utf-8"))
    nonce = req(directory["newNonce"])[2]["Replay-Nonce"]

    protected = {"url": url, "alg": alg, "nonce": nonce}
    protected.update({"jwk": jwk} if headers is None else {"kid": headers["Location"]})

    protected64 = b64(json.dumps(protected).encode("utf-8"))
    protected_input = f"{protected64}.{payload64}".encode("utf-8")

    out = exec(["openssl", "dgst", "-sha256", "-sign", key], stdin=subprocess.PIPE, cmd_input=protected_input, err="openssl error")
    data = json.dumps({"protected": protected64, "payload": payload64, "signature": b64(out)})

    try:
        return req(url, data=data.encode("utf-8"), err=err, depth=depth)
    # implement retry logic for badNonce errors
    except IndexError:
        return signed_req(url, payload, err, depth=(depth + 1))

def req_until_not (url, statuses, err):
    """keep requesting until complete"""
    while True:
        res, _, _ = req(url, err=err)
        if res["status"] in statuses:
            time.sleep(2)
            continue
    return res

def parse_pem (key):
    """parse the (account) PEM to get"""
    out = exec(["openssl", "rsa", "-in", key, "-noout", "-text"], err="openssl error")
    pattern = r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pattern, out.decode("utf-8"), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    # Make even length if odd
    pub_exp = f"0{pub_exp}" if len(pub_exp) % 2 else pub_exp

    alg = "RS256"
    jwk = {
        "e": b64(unhex(pub_exp)),
        "kty": "RSA",
        "n": b64(unhex(re.sub(r"(\s|:)", "", pub_hex))),
    }

    key_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    thumbprint = b64(hashlib.sha256(key_json.encode("utf-8")).digest())
    return thumbprint, alg, jwk

def parse_csr (csr):
    """parse the CSR to find all domains"""
    out = exec(["openssl", "req", "-in", csr, "-noout", "-text"], err=f"error loading {csr}")
    domains = set([])
    # Find Common Name in CSR
    cn = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode("utf-8"))

    if cn is not None:
        domains.add(cn.group(1))

    # Find (yay x509!!!) Subject Alt Names in CSR
    sans = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode("utf-8"), re.MULTILINE|re.DOTALL)
    if sans is not None:
        for san in sans.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    return domains

def get_directory (url):
    pass
