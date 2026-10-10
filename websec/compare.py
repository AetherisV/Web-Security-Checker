"""Offline comparison helpers for Web Security Checker reports."""

from __future__ import annotations

from typing import Any


def _header_value(report: dict[str, Any], name: str) -> Any:
    header = report.get("security_headers", {}).get(name, {})
    if not header.get("present", False):
        return None
    return header.get("value")


def _cookies_by_name(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {cookie["name"]: cookie for cookie in report.get("cookies", []) if cookie.get("name")}


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two saved reports without making network requests."""
    baseline_headers = baseline.get("security_headers", {})
    current_headers = current.get("security_headers", {})
    header_names = sorted(set(baseline_headers) | set(current_headers))

    headers = {"added": [], "removed": [], "changed": []}
    for name in header_names:
        before = _header_value(baseline, name)
        after = _header_value(current, name)
        if before is None and after is not None:
            headers["added"].append({"name": name, "current": after})
        elif before is not None and after is None:
            headers["removed"].append({"name": name, "baseline": before})
        elif before != after:
            headers["changed"].append(
                {"name": name, "baseline": before, "current": after}
            )

    baseline_cookies = _cookies_by_name(baseline)
    current_cookies = _cookies_by_name(current)
    cookie_names = sorted(set(baseline_cookies) | set(current_cookies))
    cookies = {"added": [], "removed": [], "changed": []}
    attributes = ("secure", "httponly", "samesite")

    for name in cookie_names:
        before = baseline_cookies.get(name)
        after = current_cookies.get(name)
        if before is None:
            cookies["added"].append({"name": name, "current": after})
        elif after is None:
            cookies["removed"].append({"name": name, "baseline": before})
        else:
            changes = {
                attribute: {"baseline": before.get(attribute), "current": after.get(attribute)}
                for attribute in attributes
                if before.get(attribute) != after.get(attribute)
            }
            if changes:
                cookies["changed"].append({"name": name, "attributes": changes})

    has_changes = any(headers[group] for group in headers) or any(
        cookies[group] for group in cookies
    )
    return {
        "comparison_version": "1.0",
        "has_changes": has_changes,
        "headers": headers,
        "cookies": cookies,
    }
