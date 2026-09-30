# Web Security Assessment Toolkit

**Author:** Ali Salmeh  
**Focus:** Web Application Security, Secure Coding, and Vulnerability Triage

A conservative Python command-line scanner for **authorized** web applications. It performs passive security-header checks, discovers HTML forms, and runs a harmless reflected-input canary test against query parameters. Results are available as human-readable text or JSON for later reporting and automation.

## Capabilities

- Checks CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy
- Flags HTTP transport and version disclosure indicators
- Discovers HTML forms and their actions/methods
- Tests query parameters with a unique non-executable marker
- Produces structured JSON output
- Uses only Python standard-library modules

## Responsible Use

Only scan systems you own or have explicit written authorization to assess. Use a local lab such as OWASP Juice Shop or WebGoat. This tool is for defensive triage; it does not attempt exploitation, authentication bypass, brute force, destructive testing, or arbitrary payload execution.

## Requirements

- Python 3.9+
- No third-party packages

## Usage

```bash
python3 web_security_scanner.py https://example.com --no-reflection-test
python3 web_security_scanner.py https://example.com --json
```

For an authorized local lab:

```bash
python3 web_security_scanner.py http://127.0.0.1:3000 --json
```

## Methodology

1. Validate the target URL and request the page with a clear identifying User-Agent.
2. Inspect response headers against a focused baseline of browser security controls.
3. Parse HTML forms without submitting them.
4. For URLs with query parameters, replace one parameter at a time with a unique harmless canary and check whether it is reflected in the response.
5. Report evidence and remediation guidance without claiming exploitability from reflection alone.

## Limitations

The scanner is not a full DAST platform or penetration test. It does not crawl an entire application, authenticate, execute JavaScript, understand every output context, or prove exploitability. Findings require analyst validation and should be reported according to the authorized engagement scope.

## Project Structure

```text
web-security-assessment-toolkit/
├── web_security_scanner.py
├── README.md
├── requirements.txt
└── LICENSE
```

## Author

**Ali Salmeh**  
GitHub: https://github.com/alisalme7  
LinkedIn: https://www.linkedin.com/in/ali-salmeh-464580300
