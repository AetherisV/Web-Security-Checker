"""URL validation helpers for the web-security checker."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def normalize_target_url(value: str) -> str:
    """Clean and validate a target URL.

    Rules:
    - strip surrounding whitespace
    - add https:// when no scheme is supplied
    - accept only http and https schemes
    - reject malformed URLs and empty values
    """
    if value is None:
        raise ValueError("A target URL is required.")

    candidate = value.strip()
    if not candidate:
        raise ValueError("A target URL is required.")

    if any(character.isspace() for character in candidate):
        raise ValueError("URLs must not contain whitespace.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Only http and https schemes are supported.")

    hostname = parts.hostname
    if not hostname:
        raise ValueError("Malformed URL: missing hostname.")

    netloc = parts.netloc
    if not netloc:
        raise ValueError("Malformed URL: missing network location.")

    normalized = urlunsplit((scheme, netloc, parts.path or "", parts.query, parts.fragment))
    return normalized
