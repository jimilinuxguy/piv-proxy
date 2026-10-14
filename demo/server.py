"""Example upstream. Only NGINX can publish this service to the host."""
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        identity = html.escape(self.headers.get("X-Authenticated-User", ""))
        body = ("<!doctype html><html><body><h2>Protected application</h2>"
                f"<p>Authenticated as: {identity}</p>"
                '<form method="POST" action="/logout"><button type="submit">Sign out</button></form>'
                '<p><a href="/">Home</a></p></body></html>').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
