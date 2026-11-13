"""Audit a website's HTTP security headers, cookies, CORS and TLS certificate, and grade it A-F.

Usage: python header_audit.py https://example.com [--json report.json]
Sends one ordinary GET request (plus a TLS handshake). No attack traffic.
"""
import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

PROBE_ORIGIN = "https://header-audit.example"   # sent as Origin to see whether the site reflects any origin
POINTS = {"high": 20, "medium": 10, "low": 5}
HSTS_MIN = 15552000   # 6 months, the usual minimum recommendation


def assess(url, headers, cert_days=None):
    """url: final URL after redirects. headers: [(name, value)]. cert_days: days until the TLS cert expires.
    Returns a list of findings, each mapped to a CWE and an OWASP Top 10 (2021) category."""
    h = {}
    for name, value in headers:
        h.setdefault(name.lower(), []).append(value)
    get = lambda name: ", ".join(h.get(name, []))
    https = url.lower().startswith("https://")
    found = []

    def add(severity, cwe, owasp, issue, fix):
        found.append(dict(severity=severity, cwe=cwe, owasp=owasp, issue=issue, fix=fix))

    # --- transport ---
    if not https:
        add("high", "CWE-319", "A02", "Page is served over plain HTTP", "Serve the site over HTTPS and redirect HTTP to it")
    else:
        hsts = re.search(r"max-age=(\d+)", get("strict-transport-security"), re.I)
        if not get("strict-transport-security"):
            add("high", "CWE-319", "A02", "No HSTS header: a browser can be downgraded to HTTP",
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains")
        elif not hsts or int(hsts[1]) < HSTS_MIN:
            add("medium", "CWE-319", "A02", "HSTS max-age is shorter than 6 months", "Raise max-age to 31536000")
        if cert_days is not None and cert_days < 30:
            add("medium", "-", "A02", f"TLS certificate expires in {cert_days} days", "Renew the certificate")

    # --- content security policy ---
    csp = get("content-security-policy")
    if not csp:
        add("medium", "CWE-693", "A05", "No Content-Security-Policy: no browser-side defence against XSS",
            "Add a Content-Security-Policy, starting with default-src 'self'")
    directives = {d.split()[0].lower(): d.split()[1:] for d in csp.split(";") if d.strip()}
    # only the script rules matter for XSS; 'unsafe-inline' in style-src alone is common and far less serious
    scripts = directives.get("script-src", directives.get("default-src", []))
    for weak in ("'unsafe-inline'", "'unsafe-eval'"):
        if weak in scripts:
            add("medium", "CWE-693", "A05", f"CSP allows {weak} for scripts, which defeats most of its XSS protection",
                f"Remove {weak}; use nonces or hashes")
    if "*" in scripts:
        add("medium", "CWE-693", "A05", "CSP allows scripts from any origin (*)", "List the exact origins you need")

    # --- other browser protections ---
    if not get("x-frame-options") and "frame-ancestors" not in directives:
        add("medium", "CWE-1021", "A05", "Clickjacking: any site can load this page in a frame",
            "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'")
    if get("x-content-type-options").lower() != "nosniff":
        add("low", "CWE-693", "A05", "No X-Content-Type-Options: nosniff", "Add X-Content-Type-Options: nosniff")
    if not get("referrer-policy"):
        add("low", "CWE-200", "A05", "No Referrer-Policy: full URLs can leak to other sites",
            "Add Referrer-Policy: strict-origin-when-cross-origin")
    if not get("permissions-policy"):
        add("low", "CWE-693", "A05", "No Permissions-Policy: camera, microphone and location are not restricted",
            "Add Permissions-Policy: camera=(), microphone=(), geolocation=()")

    # --- information disclosure ---
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = get(name)
        if value and (name != "server" or re.search(r"\d", value)):   # a bare "nginx" is fine, "nginx/1.18.0" is not
            add("low", "CWE-200", "A05", f"{name} header reveals software details: {value[:40]}", "Remove or genericise it")

    # --- cookies ---
    for cookie in h.get("set-cookie", []):
        name = cookie.split("=", 1)[0].strip()
        attrs = {a.strip().split("=")[0].lower() for a in cookie.split(";")[1:]}
        if https and "secure" not in attrs:
            add("medium", "CWE-614", "A02", f"Cookie '{name}' has no Secure flag", "Add the Secure attribute")
        if "httponly" not in attrs:
            add("medium", "CWE-1004", "A05", f"Cookie '{name}' has no HttpOnly flag: scripts can read it", "Add HttpOnly")
        if "samesite" not in attrs:
            add("low", "CWE-1275", "A01", f"Cookie '{name}' has no SameSite attribute (CSRF risk)", "Add SameSite=Lax or Strict")

    # --- CORS ---
    origin = get("access-control-allow-origin")
    if origin == PROBE_ORIGIN:
        with_creds = get("access-control-allow-credentials").lower() == "true"
        add("high" if with_creds else "medium", "CWE-942", "A05",
            "CORS reflects any Origin" + (" and allows credentials: other sites can read logged-in data" if with_creds else ""),
            "Allow only a fixed list of trusted origins")
    elif origin == "*":
        add("low", "CWE-942", "A05", "CORS allows every origin (*)", "Fine for public data; otherwise list trusted origins")

    return found


def grade(findings):
    score = max(0, 100 - sum(POINTS[f["severity"]] for f in findings))
    return score, next(g for limit, g in ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")) if score >= limit)


def fetch(url):
    """One GET. Returns (final_url, [(header, value)]). An error status (403, 404...) still counts: it has headers."""
    req = urllib.request.Request(url, headers={"User-Agent": "header-audit/1.0", "Origin": PROBE_ORIGIN})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.url, r.headers.items()
    except urllib.error.HTTPError as e:
        return e.url, e.headers.items()


def cert_days_left(host, port=443):
    with socket.create_connection((host, port), timeout=10) as sock:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
            return int((ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"]) - time.time()) // 86400)


def audit(url):
    if "://" not in url:
        url = "https://" + url
    if urlsplit(url).scheme not in ("http", "https"):    # refuse file://, ftp:// and friends
        raise ValueError(f"only http and https URLs are supported: {url}")
    final_url, headers = fetch(url)
    parts = urlsplit(final_url)
    days = cert_days_left(parts.hostname, parts.port or 443) if parts.scheme == "https" else None
    findings = sorted(assess(final_url, headers, days), key=lambda f: -POINTS[f["severity"]])
    score, letter = grade(findings)
    return dict(url=final_url, grade=letter, score=score, findings=findings)


def render(result):
    lines = [f"{result['url']}", f"Grade {result['grade']} ({result['score']}/100), {len(result['findings'])} findings", ""]
    lines += [f"[{f['severity'].upper():6}] {f['cwe']:8} {f['owasp']}  {f['issue']}\n{'':21}fix: {f['fix']}" for f in result["findings"]]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url", help="site to audit, for example https://example.com")
    ap.add_argument("--json", metavar="FILE", help="also write the result to a JSON file")
    args = ap.parse_args()
    try:
        result = audit(args.url)
    except (ValueError, OSError) as e:    # OSError covers DNS failures, refused connections and TLS errors
        sys.exit(f"could not audit {args.url}: {e}")
    print(render(result))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2)


if __name__ == "__main__":
    main()
