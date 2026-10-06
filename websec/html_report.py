"""Local HTML rendering for the canonical JSON report."""

from __future__ import annotations

import html
import json
from typing import Any, Mapping


def render_html_report(report: Mapping[str, Any]) -> str:
    """Render the in-memory JSON report as a self-contained, escaped HTML page."""
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    escaped_report = html.escape(report_json, quote=True)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>Web Security Checker report</title>\n"
        "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;"
        "color:#222}pre{overflow:auto;padding:1rem;background:#f4f4f4;border:1px solid #ddd;"
        "border-radius:4px;white-space:pre-wrap;overflow-wrap:anywhere}</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Web Security Checker report</h1>\n"
        "<p>This report was generated locally from the same JSON report; no additional request was made.</p>\n"
        f"<pre>{escaped_report}</pre>\n"
        "</body>\n"
        "</html>\n"
    )
