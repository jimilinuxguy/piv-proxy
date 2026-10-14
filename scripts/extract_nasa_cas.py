#!/usr/bin/env python3
"""Extract and verify NASA PIV CA certificates from the macOS keychain.

Requires macOS `security` and OpenSSL. Exports public CA certificates only.
"""
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / 'pki'
PEM_RE = re.compile(rb'-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----', re.S)


def run(*args, input_data=None, check=True):
    p = subprocess.run(args, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))} failed: {p.stderr.decode(errors='replace').strip()}")
    return p


def fail(message):
    sys.exit('ERROR: ' + message)


def parse_certs():
    raw = run('security', 'find-certificate', '-a', '-p').stdout
    unique = {}
    for block in PEM_RE.findall(raw):
        pem = block + b'\n'
        try:
            der = run('openssl', 'x509', '-outform', 'DER', input_data=pem).stdout
            digest = hashlib.sha256(der).hexdigest()
            if digest in unique:
                continue
            names = run('openssl', 'x509', '-noout', '-subject', '-issuer',
                        '-nameopt', 'RFC2253', input_data=pem).stdout.decode().splitlines()
            if len(names) < 2:
                continue
            subject, issuer = [line.split('=', 1)[1].strip() for line in names[:2]]
            text = run('openssl', 'x509', '-noout', '-text', input_data=pem).stdout.decode()
            if not re.search(r'CA:\s*TRUE', text):
                continue
            unique[digest] = dict(pem=pem, sha256=digest, subject=subject, issuer=issuer)
        except (RuntimeError, ValueError, IndexError):
            continue
    return list(unique.values())


def candidates(certs, subject_part, issuer_part=None, self_issued=False):
    return [c for c in certs if subject_part in c['subject']
            and (issuer_part is None or issuer_part in c['issuer'])
            and (not self_issued or c['subject'] == c['issuer'])]


def unique_one(certs, description):
    if len(certs) != 1:
        for c in certs:
            print(f"  {c['sha256']}  {c['subject']} <- {c['issuer']}", file=sys.stderr)
        fail(f'Expected one unique {description}; found {len(certs)}. Review the fingerprints.')
    return certs[0]


def verify_cert(cert, root, intermediates, purpose=None):
    with tempfile.TemporaryDirectory(prefix='nasa-piv-ca-') as temp:
        path = Path(temp)
        (path / 'root.pem').write_bytes(root['pem'])
        (path / 'intermediates.pem').write_bytes(b''.join(c['pem'] for c in intermediates))
        (path / 'leaf.pem').write_bytes(cert['pem'])
        cmd = ['openssl', 'verify', '-CAfile', str(path / 'root.pem')]
        if intermediates:
            cmd += ['-untrusted', str(path / 'intermediates.pem')]
        if purpose:
            cmd += ['-purpose', purpose]
        cmd.append(str(path / 'leaf.pem'))
        return run(*cmd, check=False)


def main():
    certs = parse_certs()
    if not certs:
        fail('No CA certificates found in macOS keychains.')

    root = unique_one(candidates(certs, 'CN=Federal Common Policy CA G2',
                                 self_issued=True), 'Federal Common Policy CA G2')
    treasury = unique_one(candidates(certs, 'OU=US Treasury Root CA',
                                     'CN=Federal Common Policy CA G2'),
                          'US Treasury cross-certificate')

    # Validate the Treasury cross-certificate before accepting NASA intermediates.
    result = verify_cert(treasury, root, [])
    if result.returncode:
        fail('Treasury cross-certificate did not verify: ' +
             result.stderr.decode(errors='replace').strip())

    nasa_candidates = candidates(certs, 'OU=NASA Operational CA',
                                 'OU=US Treasury Root CA')
    if not nasa_candidates:
        fail('NASA Operational CA not found in the macOS keychains.')

    valid_nasa = []
    for cert in nasa_candidates:
        result = verify_cert(cert, root, [treasury])
        if result.returncode == 0:
            valid_nasa.append(cert)
            print('Verified NASA Operational CA:', cert['sha256'])
        else:
            print('Rejected NASA Operational CA:', cert['sha256'],
                  result.stderr.decode(errors='replace').strip(), file=sys.stderr)

    if not valid_nasa:
        fail('No NASA Operational CA certificate verified to Federal Common Policy CA G2.')

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'federal-root.pem').write_bytes(root['pem'])
    (OUT / 'treasury-cross.pem').write_bytes(treasury['pem'])
    (OUT / 'nasa-operational.pem').write_bytes(b''.join(c['pem'] for c in valid_nasa))
    (OUT / 'nasa-intermediates.pem').write_bytes(treasury['pem'] +
                                                 b''.join(c['pem'] for c in valid_nasa))
    (OUT / 'client-ca.pem').write_bytes(root['pem'] + treasury['pem'] +
                                       b''.join(c['pem'] for c in valid_nasa))

    print(f'\nVerified {len(valid_nasa)} NASA Operational CA certificate(s).')
    print('Federal root SHA256:', root['sha256'])
    print('Treasury cross SHA256:', treasury['sha256'])
    print('Wrote certificates to:', OUT)
    print('\nIMPORTANT: A successful CA-chain check is not sufficient for production PIV')
    print('authentication. Enforce client-auth EKU, approved PIV policies, revocation,')
    print('and NASA-specific authorization in the authentication service.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError) as exc:
        fail(str(exc))
