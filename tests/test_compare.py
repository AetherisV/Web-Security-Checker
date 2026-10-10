from websec.compare import compare_reports


def report(headers=None, cookies=None):
    return {
        "security_headers": headers or {},
        "cookies": cookies or [],
    }


def header(value, present=True):
    return {"present": present, "value": value}


def test_compare_reports_identifies_header_changes():
    baseline = report(
        headers={
            "x-content-type-options": header("nosniff"),
            "referrer-policy": header("no-referrer"),
        }
    )
    current = report(
        headers={
            "referrer-policy": header("strict-origin"),
            "permissions-policy": header("geolocation=()"),
        }
    )

    result = compare_reports(baseline, current)

    assert result["has_changes"] is True
    assert result["headers"]["removed"] == [
        {"name": "x-content-type-options", "baseline": "nosniff"}
    ]
    assert result["headers"]["added"] == [
        {"name": "permissions-policy", "current": "geolocation=()"}
    ]
    assert result["headers"]["changed"] == [
        {
            "name": "referrer-policy",
            "baseline": "no-referrer",
            "current": "strict-origin",
        }
    ]


def test_compare_reports_identifies_cookie_attribute_changes():
    baseline = report(
        cookies=[
            {"name": "session", "secure": True, "http_only": True, "same_site": "Lax"}
        ]
    )
    current = report(
        cookies=[
            {"name": "session", "secure": False, "http_only": True, "same_site": None}
        ]
    )

    result = compare_reports(baseline, current)

    assert result["cookies"]["changed"] == [
        {
            "name": "session",
            "attributes": {
                "secure": {"baseline": True, "current": False},
                "same_site": {"baseline": "Lax", "current": None},
            },
        }
    ]


def test_compare_reports_has_no_changes_for_equal_reports():
    source = report(
        headers={"x-content-type-options": header("nosniff")},
        cookies=[{"name": "session", "secure": True, "http_only": True, "same_site": "Lax"}],
    )

    result = compare_reports(source, source)

    assert result["has_changes"] is False
    assert result["headers"] == {"added": [], "removed": [], "changed": []}
    assert result["cookies"] == {"added": [], "removed": [], "changed": []}
