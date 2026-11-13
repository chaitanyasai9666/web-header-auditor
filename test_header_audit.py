import unittest

from demo import CARELESS, HARDENED, audit_local
from header_audit import PROBE_ORIGIN, assess, audit, grade

GOOD = [("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=()"), ("Server", "nginx")]
URL = "https://site.example/"


def issues(extra=(), drop=(), url=URL, cert_days=200):
    headers = [(k, v) for k, v in GOOD if k not in drop] + list(extra)
    return [f["issue"] for f in assess(url, headers, cert_days)]


class Tests(unittest.TestCase):
    def test_hardened_https_site_is_clean(self):
        self.assertEqual(issues(), [])
        self.assertEqual(grade([]), (100, "A"))

    def test_plain_http(self):
        self.assertIn("Page is served over plain HTTP", issues(url="http://site.example/"))

    def test_hsts(self):
        self.assertIn("No HSTS header", issues(drop=["Strict-Transport-Security"])[0])
        short = issues(drop=["Strict-Transport-Security"], extra=[("Strict-Transport-Security", "max-age=3600")])
        self.assertEqual(short, ["HSTS max-age is shorter than 6 months"])

    def test_csp(self):
        self.assertIn("No Content-Security-Policy", issues(drop=["Content-Security-Policy"])[0])
        weak = issues(drop=["Content-Security-Policy"],
                      extra=[("Content-Security-Policy", "default-src * 'unsafe-inline'; frame-ancestors 'none'")])
        self.assertEqual(len(weak), 2)   # unsafe-inline and the wildcard
        styles_only = [("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")]
        self.assertEqual(issues(drop=["Content-Security-Policy"], extra=styles_only), [])

    def test_clickjacking_needs_either_header(self):
        no_csp_frame = [("Content-Security-Policy", "default-src 'self'")]
        self.assertIn("Clickjacking", issues(drop=["Content-Security-Policy"], extra=no_csp_frame)[0])
        self.assertEqual(issues(drop=["Content-Security-Policy"], extra=no_csp_frame + [("X-Frame-Options", "DENY")]), [])

    def test_missing_minor_headers(self):
        self.assertEqual(len(issues(drop=["X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"])), 3)

    def test_version_disclosure(self):
        self.assertIn("server header reveals", issues(drop=["Server"], extra=[("Server", "Apache/2.4.49")])[0])
        self.assertIn("x-powered-by", issues(extra=[("X-Powered-By", "Express")])[0])

    def test_cookie_flags(self):
        self.assertEqual(len(issues(extra=[("Set-Cookie", "sid=1; Path=/")])), 3)   # Secure, HttpOnly, SameSite
        self.assertEqual(issues(extra=[("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")]), [])
        # two cookies are checked separately
        both = issues(extra=[("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"), ("Set-Cookie", "b=2; Secure; SameSite=Lax")])
        self.assertEqual(both, ["Cookie 'b' has no HttpOnly flag: scripts can read it"])

    def test_cors(self):
        reflected = [("Access-Control-Allow-Origin", PROBE_ORIGIN), ("Access-Control-Allow-Credentials", "true")]
        self.assertEqual(assess(URL, GOOD + reflected, 200)[0]["severity"], "high")
        self.assertEqual(assess(URL, GOOD + reflected[:1], 200)[0]["severity"], "medium")
        self.assertEqual(assess(URL, GOOD + [("Access-Control-Allow-Origin", "*")], 200)[0]["severity"], "low")
        self.assertEqual(issues(extra=[("Access-Control-Allow-Origin", "https://app.site.example")]), [])

    def test_certificate_expiry(self):
        self.assertEqual(issues(cert_days=12), ["TLS certificate expires in 12 days"])

    def test_header_names_are_case_insensitive(self):
        self.assertEqual(assess(URL, [(k.upper(), v) for k, v in GOOD], 200), [])

    def test_rejects_non_web_urls(self):
        for bad in ("file:///etc/passwd", "ftp://site.example/"):
            with self.assertRaises(ValueError):
                audit(bad)

    def test_end_to_end_against_local_sites(self):
        careless = audit_local(CARELESS, reflect_origin=True)
        self.assertEqual(careless["grade"], "F")
        self.assertEqual(careless["findings"][0]["severity"], "high")
        self.assertTrue(any("CORS reflects any Origin and allows credentials" in f["issue"] for f in careless["findings"]))
        hardened = audit_local(HARDENED)
        # a local demo server has no certificate, so plain HTTP is the one thing left to flag
        self.assertEqual([f["issue"] for f in hardened["findings"]], ["Page is served over plain HTTP"])


if __name__ == "__main__":
    unittest.main()
