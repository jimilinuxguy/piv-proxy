#!/usr/bin/env python3
"""Rotate POC OIDC signing key, retaining the old public key for token verification.

Run on a single deployment coordinator; back up keys and coordinate restarts.
"""
from pathlib import Path
import os
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import hashlib
import base64

ROOT = Path(os.environ.get("OIDC_KEY_DIRECTORY", "oidc"))
ACTIVE = ROOT / "private.pem"
PREVIOUS = ROOT / "previous"

def rotate():
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    PREVIOUS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ACTIVE.exists():
        current = serialization.load_pem_private_key(ACTIVE.read_bytes(), password=None)
        public = current.public_key()
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        kid = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
        destination = PREVIOUS / (kid + ".pem")
        destination.write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        destination.chmod(0o600)
    new = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private = new.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd, name = tempfile.mkstemp(dir=ROOT, prefix=".private-", suffix=".pem")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(private)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, ACTIVE)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print("OIDC signing key rotated. Retain old public keys at least until all old ID tokens expire.")

if __name__ == "__main__":
    rotate()
