#!/usr/bin/env python3
"""Web Security Assessment Toolkit
Author: Ali Salmeh

Defensive scanner for authorized web applications. Performs passive header
checks and a conservative reflected-input test using a unique harmless marker.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

USER_AGENT = "AliSalmeh-WebSecurityScanner/1.0"
TIMEOUT = 10


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    evidence: str
    recommendation: str


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self.current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag.lower() == "form":
            self.current = {"action": values.get("action") or "", "method": (values.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self.current)
        elif self.current is not None and tag.lower() in {"input", "textarea", "select"}:
            name = values.get("name")
            if name:
                self.current["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self.current = None


def fetch(url: str, method: str = "GET", data: bytes | None = None) -> tuple[int, dict[str, str], str]:
    request = Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"})
    with urlopen(request, timeout=TIMEOUT) as response:
        raw = response.read(1_000_000)
        return response.status, {k.lower(): v for k, v in response.headers.items()}, raw.decode("utf-8", errors="replace")


def add_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output = []
    for key, current in params:
        if key == name:
            output.append((key, value)); replaced = True
        else:
            output.append((key, current))
    if not replaced:
        output.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(output)))


def passive_checks(headers: dict[str, str], scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    checks = {
        "content-security-policy": ("Missing Content-Security-Policy", "Define a restrictive CSP and reduce unsafe inline/script sources."),
        "x-content-type-options": ("Missing X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("Missing Referrer-Policy", "Set a restrictive policy such as strict-origin-when-cross-origin."),
        "permissions-policy": ("Missing Permissions-Policy", "Explicitly limit browser capabilities not required by the application."),
    }
    for header, (title, recommendation) in checks.items():
        if header not in headers:
            findings.append(Finding("security-header", "medium", title, f"{header} was not present in the response.", recommendation))
    if scheme != "https":
        findings.append(Finding("transport", "high", "Application is served over HTTP", "Target URL does not use HTTPS.", "Use HTTPS and redirect HTTP to HTTPS; enable HSTS after HTTPS is correctly deployed."))
    if "strict-transport-security" not in headers and scheme == "https":
        findings.append(Finding("security-header", "medium", "Missing Strict-Transport-Security", "HSTS was not present on an HTTPS response.", "Set HSTS with an appropriate max-age after validating HTTPS across the domain."))
    server = headers.get("server")
    if server and re.search(r"\d", server):
        findings.append(Finding("information-disclosure", "low", "Server header may disclose version information", server, "Minimize unnecessary version disclosure in response headers."))
    return findings


def scan(url: str, do_reflected_test: bool = True) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Use a complete http:// or https:// URL")
    status, headers, body = fetch(url)
    findings = passive_checks(headers, parsed.scheme)
    parser = FormParser(); parser.feed(body)
    forms = []
    for form in parser.forms:
        forms.append({"action": urljoin(url, form["action"] or url), "method": form["method"], "input_count": len(form["inputs"])})
    marker = "ALISALME7_CANARY_" + uuid.uuid4().hex[:10]
    reflected_test = {"performed": False, "parameter": None, "marker": marker, "reflected": False}
    if do_reflected_test and parsed.query:
        for parameter, _ in parse_qsl(parsed.query, keep_blank_values=True):
            test_url = add_query(url, parameter, marker)
            try:
                _, _, test_body = fetch(test_url)
            except Exception:
                continue
            reflected_test = {"performed": True, "parameter": parameter, "marker": marker, "reflected": marker in test_body}
            if marker in test_body:
                findings.append(Finding("input-validation", "medium", "Reflected input detected", f"The harmless canary was reflected for query parameter '{parameter}'.", "Contextually encode output and validate input; confirm exploitability manually in an authorized test environment."))
                break
    return {"target": url, "status": status, "response_headers": headers, "forms": forms, "findings": [asdict(f) for f in findings], "reflected_input_test": reflected_test, "limitations": ["This is a triage tool, not a penetration test.", "Only scan systems you own or are explicitly authorized to assess."]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Perform a conservative security assessment of an authorized web target.")
    parser.add_argument("url", help="Complete authorized URL")
    parser.add_argument("--no-reflection-test", action="store_true", help="Run passive checks only")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()
    try:
        result = scan(args.url, not args.no_reflection_test)
    except Exception as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr); return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("=== Web Security Assessment Toolkit ===")
        print("Author: Ali Salmeh")
        print(f"Target: {result['target']} | HTTP {result['status']}")
        print(f"Forms discovered: {len(result['forms'])}")
        print(f"Findings: {len(result['findings'])}")
        for item in result['findings']:
            print(f"[{item['severity'].upper()}] {item['title']} — {item['evidence']}")
        print(f"Reflected-input test: {result['reflected_input_test']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
