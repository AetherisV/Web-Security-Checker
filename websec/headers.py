"""Security-header normalization and reporting."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping


HEADER_DESCRIPTIONS: Dict[str, str] = {
    "Content-Security-Policy": "Controls which resources the browser may load and execute.",
    "Strict-Transport-Security": "Forces HTTPS and helps protect transport security over time.",
    "X-Frame-Options": "Prevents the page from being embedded in a frame or iframe.",
    "X-Content-Type-Options": "Prevents browsers from MIME-sniffing a response away from the declared type.",
    "Referrer-Policy": "Controls how much referrer information is exposed to other origins.",
    "Permissions-Policy": "Restricts browser features and APIs that a page can use.",
}


def normalize_headers(raw_headers: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> Dict[str, str]:
    """Return a lower-case header dictionary with string values."""
    normalized: Dict[str, str] = {}
    if raw_headers is None:
        return normalized

    if hasattr(raw_headers, "items"):
        pairs = raw_headers.items()
    else:
        pairs = raw_headers

    for key, value in pairs:
        if value is None:
            continue
        normalized[str(key).lower()] = str(value)
    return normalized


def build_security_header_report(raw_headers: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> Dict[str, Dict[str, Any]]:
    """Produce the required JSON-friendly summary for the six supported security headers."""
    headers = normalize_headers(raw_headers)
    report: Dict[str, Dict[str, Any]] = {}

    for header_name in [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]:
        observed_value = headers.get(header_name.lower())
        report[header_name] = {
            "present": observed_value is not None,
            "value": observed_value if observed_value is not None else None,
            "description": HEADER_DESCRIPTIONS[header_name],
        }

    return report
