# Web Security Checker

A lightweight Python CLI for **passive inspection** of common web-security headers and cookie attributes on authorized targets.

> **Authorization reminder:** Only inspect websites and systems that you own or are explicitly authorized to test.

Web Security Checker makes one normal HTTP GET request to a supplied URL and reports observable response security configuration. It can also compare saved reports to identify configuration drift and evaluate a live inspection against a JSON security policy.

It is designed for security visibility and regression checking—not for exploitation, penetration testing, or a complete vulnerability verdict.

## Features

- Passive inspection of six common HTTP security headers
- Cookie attribute reporting for observed `Set-Cookie` response headers
- JSON output for automation and archival
- Self-contained HTML reports for review and sharing
- Offline baseline-versus-current report comparison
- JSON policy evaluation for authorized URLs
- Optional nonzero exit status when policy requirements do not match
- Automated tests and GitHub Actions CI

## What it checks

The inspector reports exactly these six headers:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

It also records observable cookie information from `Set-Cookie` response headers:

- Cookie name
- `Secure`
- `HttpOnly`
- `SameSite`

Missing `Secure` or `HttpOnly` flags are reported as `false`. `SameSite` is reported as `null` when it is absent or cannot be reliably parsed from the observed response. Repeated `Set-Cookie` fields are read from the same response without triggering another request.

## Installation

```bash
git clone https://github.com/AetherisV/Web-Security-Checker.git
cd Web-Security-Checker

python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

The CLI provides three commands:

```bash
python checker.py inspect URL
python checker.py compare BASELINE_REPORT CURRENT_REPORT
python checker.py check URL --policy POLICY_FILE
```

### Inspect an authorized URL

```bash
python checker.py inspect https://example.com
python checker.py inspect https://example.com --output report.json
python checker.py inspect https://example.com --html-output report.html
python checker.py inspect https://example.com --timeout 15
python checker.py inspect https://example.com --follow-redirects
```

### Compare saved reports

Comparison runs offline against two existing JSON reports. It does not make a network request.

```bash
python checker.py compare examples/baseline.json examples/current.json