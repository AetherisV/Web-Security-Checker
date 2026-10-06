"""Report construction for the web-security checker."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from websec.headers import build_security_header_report

_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_PAIR_START = re.compile(r"\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=")


def _iso8601_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _as_list(value: Optional[Any]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _split_combined_cookie_header(value: str) -> List[str]:
    """Split merged Set-Cookie fields without splitting an Expires date."""
    headers: List[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == "," and not quoted and _COOKIE_PAIR_START.match(value[index + 1:]):
            headers.append(value[start:index].strip())
            start = index + 1
    headers.append(value[start:].strip())
    return headers


def _split_cookie_parts(value: str) -> List[str]:
    parts: List[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def _cookie_attribute_state(attributes: List[tuple[str, Optional[str]]], name: str) -> Optional[bool]:
    matching = [value for key, value in attributes if key == name]
    if not matching:
        return False
    if any(value is not None for value in matching):
        return None
    return True


def _parse_cookie_headers(raw_headers: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if raw_headers is None:
        return []

    if hasattr(raw_headers, "getlist"):
        cookie_values = raw_headers.getlist("Set-Cookie")
    else:
        cookie_values = raw_headers.get("Set-Cookie")
        if cookie_values is None:
            return []
        if isinstance(cookie_values, str):
            cookie_values = [cookie_values]

    cookies: List[Dict[str, Any]] = []
    for cookie_header in cookie_values or []:
        if not cookie_header:
            continue

        for individual_header in _split_combined_cookie_header(str(cookie_header)):
            parts = _split_cookie_parts(individual_header)
            if not parts or "=" not in parts[0]:
                continue

            name, value = parts[0].split("=", 1)
            name = name.strip()
            if not _COOKIE_NAME.fullmatch(name):
                continue

            attributes: List[tuple[str, Optional[str]]] = []
            for part in parts[1:]:
                if not part:
                    continue
                key, separator, attribute_value = part.partition("=")
                attributes.append((key.strip().lower(), attribute_value.strip() if separator else None))

            same_site_values = [value for key, value in attributes if key == "samesite"]
            same_site = None
            if len(same_site_values) == 1 and same_site_values[0]:
                same_site = same_site_values[0]
            elif len(same_site_values) > 1 and all(
                value and value.lower() == same_site_values[0].lower() for value in same_site_values
            ):
                same_site = same_site_values[0]

            cookies.append({
                "name": name,
                "value": value.strip(),
                "secure": _cookie_attribute_state(attributes, "secure"),
                "http_only": _cookie_attribute_state(attributes, "httponly"),
                "same_site": same_site,
                "notes": "Attributes reflect the observed Set-Cookie field only; omitted Secure and HttpOnly are reported as false, while SameSite is null when omitted or not reliably parseable. Browser enforcement cannot be confirmed from a single passive response.",
            })

    return cookies


def build_report(
    input_url: str,
    final_url: Optional[str],
    status_code: Optional[int],
    response_time_ms: Optional[int],
    response_headers: Optional[Mapping[str, Any]] = None,
    redirect_location: Optional[str] = None,
    notes: Optional[Iterable[str]] = None,
    cookie_headers: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical JSON report for the single-request checker."""
    observed_headers = dict(response_headers or {})
    if redirect_location is None:
        redirect_location = observed_headers.get("Location") or observed_headers.get("location")

    security_headers = build_security_header_report(observed_headers)
    cookie_entries = _parse_cookie_headers(cookie_headers if cookie_headers is not None else response_headers)

    note_list = _as_list(notes)
    authorization_reminder = "Authorization reminder: only inspect targets you own or are explicitly authorized to test."
    if not any(authorization_reminder in note for note in note_list):
        note_list.insert(0, authorization_reminder)

    report = {
        "tool": "web-security-checker",
        "checked_at": _iso8601_utc(),
        "target": {
            "input_url": input_url,
            "final_url": final_url,
            "status_code": status_code,
            "response_time_ms": response_time_ms,
        },
        "http": {
            "redirect_location": redirect_location,
            "server": observed_headers.get("Server") or observed_headers.get("server"),
            "x_powered_by": observed_headers.get("X-Powered-By") or observed_headers.get("x-powered-by"),
        },
        "security_headers": security_headers,
        "cookies": cookie_entries,
        "notes": note_list,
    }
    return report
