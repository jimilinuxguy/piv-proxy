#!/usr/bin/env python3
"""Refresh a verified NASA Operational CA CRL, preserving the last good file on errors."""
import argparse
import datetime as dt
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener

from cryptography import x509

DEFAULT_URL = "http://hc.nasa.gov/combinedCRL5.crl"
DEFAULT_HOSTS = {"hc.nasa.gov", "pki.treasury.gov"}
CERT_PATTERN = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
MAX_BYTES = 32 * 1024 * 1024


def load_crl(data):
    return (x509.load_pem_x509_crl(data) if b"-----BEGIN X509 CRL-----" in data
            else x509.load_der_x509_crl(data))


def verify_crl(data, issuer_bundle, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    crl = load_crl(data)
    if crl.next_update_utc is None or not crl.last_update_utc <= now < crl.next_update_utc:
        raise ValueError("CRL is expired or not yet valid")
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        pass
    else:
        raise ValueError("delta CRLs are not supported")
    try:
        idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
    except x509.ExtensionNotFound:
        idp = None
    if idp and (idp.indirect_crl or idp.only_some_reasons or
                idp.only_contains_attribute_certs or idp.only_contains_ca_certs):
        raise ValueError("restricted or indirect CRL unsupported")
    certs = [x509.load_pem_x509_certificate(match.group(0))
             for match in CERT_PATTERN.finditer(issuer_bundle)]
    if not certs:
        raise ValueError("issuer bundle contains no certificates")
    for issuer in certs:
        if issuer.subject != crl.issuer or not crl.is_signature_valid(issuer.public_key()):
            continue
        try:
            usage = issuer.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if not usage.crl_sign:
                continue
        except x509.ExtensionNotFound:
            continue
        try:
            crl_aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            issuer_ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            if crl_aki.key_identifier and crl_aki.key_identifier != issuer_ski.digest:
                continue
        except x509.ExtensionNotFound:
            pass
        return crl
    raise ValueError("CRL signature/issuer does not match an authorized issuer certificate")


def refresh(url, issuer_path, output_path, allowed_hosts=None):
    parsed = urlparse(url)
    allowed_hosts = allowed_hosts or DEFAULT_HOSTS
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in allowed_hosts:
        raise ValueError("CRL URL must be an explicitly approved NASA/Treasury endpoint")
    if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
        raise ValueError("Unsupported CRL URL authority")
    issuer_bundle = Path(issuer_path).read_bytes()
    req = Request(url, headers={"User-Agent": "local-piv-crl-refresh/1.0"})
    class RestrictedRedirects(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            candidate = urlparse(newurl)
            if (candidate.scheme not in {"http", "https"} or
                    candidate.hostname not in allowed_hosts or
                    candidate.username or candidate.password or
                    candidate.port not in (None, 80, 443)):
                raise ValueError("CRL redirect to unapproved endpoint")
            return super().redirect_request(request, fp, code, msg, headers, newurl)

    with build_opener(RestrictedRedirects()).open(req, timeout=30) as response:
        final_url = urlparse(response.geturl())
        if (final_url.scheme not in {"http", "https"} or final_url.hostname not in allowed_hosts
                or final_url.username or final_url.password):
            raise ValueError("CRL endpoint redirected to unapproved host")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("CRL exceeds size limit")
    crl = verify_crl(data, issuer_bundle)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(prefix=".nasa-crl-", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(tmpname, 0o644)
        os.replace(tmpname, destination)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)
    print(f"CRL verified and installed: {destination}")
    print(f"Issuer: {crl.issuer.rfc4514_string()}")
    print(f"Current until: {crl.next_update_utc.isoformat()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("PIV_CRL_URL", DEFAULT_URL))
    parser.add_argument("--issuer", default="pki/nasa-operational.pem")
    parser.add_argument("--output", default="pki/nasa-leaf.crl")
    args = parser.parse_args()
    try:
        refresh(args.url, args.issuer, args.output)
    except Exception as exc:
        print(f"CRL refresh failed (existing CRL preserved): {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
