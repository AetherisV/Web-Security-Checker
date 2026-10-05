# Web Security Checker

A lightweight, ethical Python CLI for inspecting common web-security headers and cookie attributes on authorized targets.

Authorization reminder: Only inspect targets you own or are explicitly authorized to test.

This tool is a lightweight, passive inspection utility for a single HTTP GET request to a supplied URL. It reports the state of six common security headers and the cookie attributes that can be observed from the response headers, without claiming a full vulnerability verdict.

## What it checks

Version 1 checks exactly these six headers and no others:

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

It also records cookie attributes for Secure, HttpOnly, and SameSite when they are present in the response headers.

## Installation

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux / macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
web-security-checker https://example.com
web-security-checker https://example.com --output report.json
web-security-checker https://example.com --timeout 15
web-security-checker https://example.com --follow-redirects
web-security-checker https://example.com --verbose
```

### Command options

- `--output FILE`: write the JSON report to a file while still printing JSON to stdout.
- `--timeout SECONDS`: set the HTTP timeout in seconds (default: 10).
- `--follow-redirects`: follow redirects during the request flow.
- `--verbose`: include additional informational notes in the JSON report.

## Terminal example

```bash
$ web-security-checker https://example.com
{
  "tool": "web-security-checker",
  "checked_at": "2026-10-05T12:00:00Z",
  "target": {
    "input_url": "https://example.com",
    "final_url": "https://example.com",
    "status_code": 200,
    "response_time_ms": 128
  },
  "http": {
    "redirect_location": null,
    "server": "nginx",
    "x_powered_by": null
  },
  "security_headers": {
    "Content-Security-Policy": {
      "present": true,
      "value": "default-src 'self'",
      "description": "Controls which resources the browser may load and execute."
    },
    "Strict-Transport-Security": {
      "present": false,
      "value": null,
      "description": "Forces HTTPS and helps protect transport security over time."
    },
    "X-Frame-Options": {
      "present": true,
      "value": "DENY",
      "description": "Prevents the page from being embedded in a frame or iframe."
    },
    "X-Content-Type-Options": {
      "present": true,
      "value": "nosniff",
      "description": "Prevents browsers from MIME-sniffing a response away from the declared type."
    },
    "Referrer-Policy": {
      "present": true,
      "value": "strict-origin-when-cross-origin",
      "description": "Controls how much referrer information is exposed to other origins."
    },
    "Permissions-Policy": {
      "present": false,
      "value": null,
      "description": "Restricts browser features and APIs that a page can use."
    }
  },
  "cookies": [
    {
      "name": "sessionid",
      "value": "abc123",
      "secure": true,
      "http_only": true,
      "same_site": "Lax",
      "notes": "Cookie attributes observed from the Set-Cookie response header when present; browser enforcement cannot always be inferred reliably from a single passive response."
    }
  ],
  "notes": [
    "Authorization reminder: only inspect targets you own or are explicitly authorized to test."
  ]
}
```

## JSON example

See [examples/sample-report.json](examples/sample-report.json) for a representative report.

## Limitations

- This is a passive, single-request inspection tool.
- It does not crawl, enumerate subdomains, scan ports, or test for vulnerabilities.
- It does not infer browser enforcement beyond what is exposed in the response headers.
- Cookie attributes may be absent or not reliably observable in some deployments and may require a browser context to confirm.
- It is not a full vulnerability scanner and should not be used as a security verdict tool.

## Roadmap

- Improve JSON output readability and portability.
- Add clearer notes for missing or contextual headers.
- Expand documentation and examples for common deployment patterns.
- Keep the tool focused on authorized, passive inspection.

## Ethical use

This project is intended for authorized testing only. Use it on systems that you own or operate, or on systems where you have explicit written permission to evaluate them.

This tool is not a full vulnerability scanner and is meant for passive header and cookie inspection only.
