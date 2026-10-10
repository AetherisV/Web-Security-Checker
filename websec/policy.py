"""Owner-defined HTTP security policy evaluation helpers."""

from __future__ import annotations

from typing import Any


def _header(report: dict[str, Any], name: str) -> dict[str, Any]:
    return report.get("security_headers", {}).get(name, {})


def _cookie_by_name(report: dict[str, Any], name: str) -> dict[str, Any] | None:
    for cookie in report.get("cookies", []):
        if cookie.get("name") == name:
            return cookie
    return None


def _mismatch(subject: str, message: str) -> dict[str, str]:
    return {"subject": subject, "message": message}


def evaluate_policy(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a report against an owner-defined policy without scoring risk."""
    mismatches: list[dict[str, str]] = []

    for name, rules in policy.get("headers", {}).items():
        header = _header(report, name)
        present = bool(header.get("present", False))
        value = header.get("value")
        observations = header.get("observations", {})

        if rules.get("required") and not present:
            mismatches.append(
                _mismatch("header", f'Required header "{name}" was not observed.')
            )
            continue
        if not present:
            continue

        expected_value = rules.get("expected_value")
        if expected_value is not None and str(value).lower() != str(expected_value).lower():
            mismatches.append(
                _mismatch(
                    "header",
                    f'Header "{name}" was "{value}"; policy expects "{expected_value}".',
                )
            )

        allowed_values = rules.get("allowed_values")
        if allowed_values is not None:
            normalized = str(value).lower()
            allowed = {str(item).lower() for item in allowed_values}
            if normalized not in allowed:
                mismatches.append(
                    _mismatch(
                        "header",
                        f'Header "{name}" was "{value}"; it is not allowed by policy.',
                    )
                )

        min_max_age = rules.get("min_max_age")
        if min_max_age is not None:
            max_age = observations.get("max_age")
            if not isinstance(max_age, int) or max_age < min_max_age:
                shown_value = "not observed" if max_age is None else str(max_age)
                mismatches.append(
                    _mismatch(
                        "header",
                        f'HSTS max-age was {shown_value}; policy requires at least {min_max_age}.',
                    )
                )

        if rules.get("require_include_subdomains") and not observations.get(
            "include_subdomains", False
        ):
            mismatches.append(
                _mismatch(
                    "header",
                    'HSTS did not include "includeSubDomains" as required by policy.',
                )
            )

    cookie_rules = policy.get("cookies", {})
    for name in cookie_rules.get("session_cookie_names", []):
        cookie = _cookie_by_name(report, name)
        if cookie is None:
            mismatches.append(
                _mismatch("cookie", f'Required session cookie "{name}" was not observed.')
            )
            continue

        for attribute, rule_name, label in (
            ("secure", "require_secure", "Secure"),
            ("httponly", "require_httponly", "HttpOnly"),
        ):
            if cookie_rules.get(rule_name) and not cookie.get(attribute, False):
                mismatches.append(
                    _mismatch(
                        "cookie",
                        f'Cookie "{name}" was observed without {label}.',
                    )
                )

        if cookie_rules.get("require_samesite") and not cookie.get("samesite"):
            mismatches.append(
                _mismatch(
                    "cookie",
                    f'Cookie "{name}" was observed without SameSite.',
                )
            )

    return {
        "policy_version": policy.get("policy_version"),
        "matched": not mismatches,
        "mismatches": mismatches,
    }
