"""Single-request HTTP client for the web-security checker."""

from __future__ import annotations

import requests


def fetch_url(url: str, timeout: float = 10.0, follow_redirects: bool = False) -> requests.Response:
    """Perform one normal GET request to the supplied URL."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "web-security-checker/0.1.0 (+passive header inspection; authorized use only)",
    })
    response = session.get(
        url,
        timeout=timeout,
        verify=True,
        allow_redirects=follow_redirects,
    )
    return response
