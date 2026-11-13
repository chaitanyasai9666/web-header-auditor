"""Audit two local demo sites, one careless and one hardened: python demo.py
Both run on 127.0.0.1 only, so the demo needs no internet and touches nobody else's server."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from header_audit import audit, render

CARELESS = [("Server", "Apache/2.4.49 (Unix)"), ("X-Powered-By", "PHP/7.2.1"),
            ("Set-Cookie", "session=abc123; Path=/"),
            ("Content-Security-Policy", "default-src * 'unsafe-inline'"),
            ("Access-Control-Allow-Credentials", "true")]
HARDENED = [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Strict")]


def serve(headers, reflect_origin=False):
    """Start a local site that answers every GET with the given headers. Returns (server, url)."""
    class Site(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for name, value in headers:
                if name != "Server":      # send_response already sent it, from version_string below
                    self.send_header(name, value)
            if reflect_origin and self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.end_headers()
            self.wfile.write(b"ok")

        def version_string(self):     # let the header list decide what Server says
            return dict(headers).get("Server", "demo")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/"


def audit_local(headers, reflect_origin=False):
    server, url = serve(headers, reflect_origin)
    try:
        return audit(url)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    for title, headers, reflect in (("CARELESS SITE", CARELESS, True), ("HARDENED SITE", HARDENED, False)):
        print(f"=== {title} ===\n{render(audit_local(headers, reflect))}\n")
