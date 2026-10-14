"""LOCAL DEMO ONLY: NGINX validates TLS chain; app checks NASA identity and EKU.
Not production PIV auth: revocation, policy allowlisting and authorization incomplete.
"""
import datetime
import html
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ('/', '/healthz'):
            self.send_error(404)
            return
        if self.path == '/healthz':
            self.respond(200, 'ok')
            return
        try:
            if self.headers.get('X-PIV-Verified') != 'SUCCESS':
                raise ValueError('NGINX did not verify the client certificate')
            encoded = self.headers.get('X-PIV-Cert', '')
            if not encoded:
                raise ValueError('Missing client certificate')
            cert = x509.load_pem_x509_certificate(unquote(encoded).encode('ascii'))
            now = datetime.datetime.now(datetime.timezone.utc)
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                raise ValueError('Certificate expired or not yet valid')
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                raise ValueError('Certificate does not permit TLS client authentication')
            nasa_issuer = os.getenv('NASA_ISSUER', 'NASA Operational CA')
            if not any(nasa_issuer == a.value for a in cert.issuer):
                raise ValueError('Certificate issuer is not NASA Operational CA')
            required = {x.strip() for x in os.getenv('REQUIRED_POLICY_OIDS', '').split(',') if x.strip()}
            if required:
                policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
                actual = {p.policy_identifier.dotted_string for p in policies}
                if not actual.intersection(required):
                    raise ValueError('Missing approved PIV certificate policy')
            common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            name = common_names[0].value if common_names else cert.subject.rfc4514_string()
            self.respond(200, '<!doctype html><html><body><h2>mTLS succeeded</h2>'
                         '<p>NASA PIV certificate accepted for LOCAL TEST.</p>'
                         f'<p>Subject: {html.escape(name)}</p>'
                         f'<p>Issuer: {html.escape(cert.issuer.rfc4514_string())}</p>'
                         '<p><strong>Not production authorization: revocation checks are not enabled.</strong></p>'
                         '</body></html>', 'text/html; charset=utf-8')
        except Exception as exc:
            self.respond(403, 'PIV rejected: ' + html.escape(str(exc)))

    def respond(self, status, body, content_type='text/plain; charset=utf-8'):
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
