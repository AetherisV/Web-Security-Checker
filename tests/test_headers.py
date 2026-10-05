from websec.headers import build_security_header_report


EXPECTED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def test_build_security_header_report_contains_exact_supported_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }

    report = build_security_header_report(headers)

    assert list(report.keys()) == EXPECTED_HEADERS
    for header_name in EXPECTED_HEADERS:
        assert "present" in report[header_name]
        assert "value" in report[header_name]
        assert "description" in report[header_name]
        assert report[header_name]["present"] is True
        assert report[header_name]["value"] == headers[header_name]


def test_build_security_header_report_marks_missing_headers_as_absent():
    report = build_security_header_report({})

    for header_name in EXPECTED_HEADERS:
        assert report[header_name]["present"] is False
        assert report[header_name]["value"] is None
