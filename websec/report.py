"""Report construction for the web-security checker."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from websec.headers import build_security_header_report


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
    for cookie_header in cookie_values:
        if not cookie_header:
            continue

        parts = [part.strip() for part in str(cookie_header).split(";")]
        if not parts or "=" not in parts[0]:
            continue

        name_value = parts[0].split("=", 1)
        name = name_value[0].strip()
        value = name_value[1].strip() if len(name_value) > 1 else ""

        lower_parts = [part.lower() for part in parts[1:]]
        secure = "secure" in lower_parts
        http_only = "httponly" in lower_parts
        same_site = None
        for part in parts[1:]:
            if part.lower().startswith("samesite="):
                same_site = part.split("=", 1)[1].strip() if "=" in part else None
                break

        cookie_entry = {
            "name": name,
            "value": value,
            "secure": secure,
            "http_only": http_only,
            "same_site": same_site,
            "notes": "Cookie attributes observed from the Set-Cookie response header when present; browser enforcement cannot always be inferred reliably from a single passive response.",
        }
        cookies.append(cookie_entry)

    return cookies


def build_report(
    input_url: str,
    final_url: Optional[str],
    status_code: Optional[int],
    response_time_ms: Optional[int],
    response_headers: Optional[Mapping[str, Any]] = None,
    redirect_location: Optional[str] = None,
    notes: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Build the canonical JSON report for the single-request checker."""
    observed_headers = dict(response_headers or {})
    if redirect_location is None:
        redirect_location = observed_headers.get("Location") or observed_headers.get("location")

    security_headers = build_security_header_report(observed_headers)
    cookie_entries = _parse_cookie_headers(response_headers)

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
