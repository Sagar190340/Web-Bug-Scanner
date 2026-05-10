#!/usr/bin/env python3
"""
ITS OVER – a lightweight web-security-testing helper.

Features
--------
1️⃣ Fetch a URL and inspect the HTTP response.
2️⃣ Basic “suspicious-content” heuristics (keyword list, external scripts).
3️⃣ Security-header audit (CSP, X-Content-Type-Options, X-Frame-Options, …).
4️⃣ TLS/HTTPS validation.
5️⃣ Optional VirusTotal lookup (requires a VT API key).

Usage
-----
>>> from its_over import scan_url
>>> result = scan_url("https://example.com")
>>> print(result)

Command line:
    python its_over.py https://example.com
"""

import argparse
import json
import ssl
import sys
from collections import Counter
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# ----------------------------------------------------------------------
# Configuration – edit as needed
# ----------------------------------------------------------------------
VT_API_KEY = ""  # <‑‑ put your VirusTotal v3 API key here (optional)

SUSPICIOUS_KEYWORDS = {
    "eval",
    "document.write",
    "unescape",
    "atob",
    "base64",
    "iframe",
    "onerror",
    "onload",
    "javascript:",
    "script src",
    "window.location",
    "settimeout",
    "setinterval",
}

# ----------------------------------------------------------------------
# Helper utilities
# ----------------------------------------------------------------------
def _fetch(url: str) -> requests.Response:
    headers = {"User-Agent": "ITS-OVER/1.0 (+https://github.com/Sagar190340/Sagar-Dhar)"}
    return requests.get(url, headers=headers, timeout=15, verify=True)

def _is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"

def _tls_valid(url: str) -> bool:
    if not _is_https(url):
        return False
    host = urlparse(url).hostname
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket=ssl.SSLSocket(), server_hostname=host) as s:
            s.connect((host, 443))
        return True
    except Exception:
        return False

def _keyword_score(html: str) -> int:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ").lower()
    return sum(kw in text for kw in SUSPICIOUS_KEYWORDS)

def _external_script_score(soup: BeautifulSoup) -> int:
    page_host = urlparse(soup.base_url or "").hostname
    score = 0
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        parsed = urlparse(src)
        if parsed.scheme and parsed.hostname != page_host:
            score += 1
    return score

def _header_report(resp: requests.Response) -> dict:
    needed = {
        "Content-Security-Policy": False,
        "X-Content-Type-Options": False,
        "X-Frame-Options": False,
        "X-XSS-Protection": False,
        "Referrer-Policy": False,
        "Strict-Transport-Security": _is_https(resp.url),
    }
    return {hdr: hdr in resp.headers for hdr in needed}

def _virus_total_scan(url: str) -> dict | None:
    if not VT_API_KEY:
        return None
    headers = {"x-apikey": VT_API_KEY}
    vt_url = "https://www.virustotal.com/api/v3/urls"
    resp = requests.post(vt_url, data={"url": url}, headers=headers, timeout=10)
    if resp.status_code != 200:
        return None
    analysis_id = resp.json()["data"]["id"]
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=10,
    )
    if result.status_code != 200:
        return None
    return result.json()["data"]["attributes"]

def scan_url(url: str) -> dict:
    try:
        resp = _fetch(url)
    except Exception as e:
        return {"error": f"Unable to fetch: {e}"}

    soup = BeautifulSoup(resp.text, "html.parser")
    soup.base_url = resp.url

    report = {
        "url": resp.url,
        "http_status": resp.status_code,
        "https": _is_https(resp.url),
        "tls_valid": _tls_valid(resp.url),
        "security_headers": _header_report(resp),
        "suspicious_keyword_hits": _keyword_score(resp.text),
        "external_script_hits": _external_script_score(soup),
    }

    vt = _virus_total_scan(url)
    if vt:
        report["virustotal"] = {
            "malicious": vt["stats"]["malicious"],
            "suspicious": vt["stats"]["suspicious"],
            "harmless": vt["stats"]["harmless"],
            "total": sum(vt["stats"].values()),
            "summary": vt.get("result", "N/A"),
        }

    score = (
        report["suspicious_keyword_hits"]
        + report["external_script_hits"]
        + (0 if report["https"] else 2)
    )
    report["overall_score"] = min(score, 10)
    return report

def _cli():
    parser = argparse.ArgumentParser(description="ITS OVER – quick web-security scanner")
    parser.add_argument("url", help="Target URL (include scheme, e.g. https://)")
    parser.add_argument("--json", action="store_true", help="Print raw JSON")
    args = parser.parse_args()

    result = scan_url(args.url)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    if "error" in result:
        print("Error:", result["error"])
        return
    print(f"\n=== ITS OVER scan report for {result['url']} ===")
    print(f"HTTP status : {result['http_status']}")
    print(f"HTTPS       : {'yes' if result['https'] else 'no'}")
    print(f"TLS valid   : {'yes' if result['tls_valid'] else 'no'}")
    print("\nSecurity-header check:")
    for hdr, ok in result["security_headers"].items():
        print(f"  {hdr:27}: {'OK' if ok else 'MISSING'}")
    print("\nHeuristics:")
    print(f"  Suspicious keyword hits : {result['suspicious_keyword_hits']}")
    print(f"  External script hits    : {result['external_script_hits']}")
    print(f"  Overall risk score (0-10): {result['overall_score']}")
    vt = result.get("virustotal")
    if vt:
        print("\nVirusTotal summary:")
        print(f"  Malicious : {vt['malicious']}")
        print(f"  Suspicious: {vt['suspicious']}")
        print(f"  Harmless  : {vt['harmless']}")
        print(f"  Total scans: {vt['total']}")
    print("\nInterpretation:")
    print("  ⚠️  Red flags – investigate further." if result["overall_score"] >= 5 else "  ✅  No obvious issues detected.")

if __name__ == "__main__":
    _cli()
