from websec.report import build_report


def test_build_report_contains_required_top_level_fields():
    report = build_report(
        input_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_time_ms=42,
        response_headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "Server": "nginx",
            "X-Powered-By": "ExampleServer",
            "Location": "https://example.com/redirected",
            "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
        },
        notes=["Authorization reminder: only inspect targets you own or are explicitly authorized to test."],
    )

    assert report["tool"] == "web-security-checker"
    assert "checked_at" in report
    assert set(report.keys()) == {"tool", "checked_at", "target", "http", "security_headers", "cookies", "notes"}
    assert report["target"]["input_url"] == "https://example.com"
    assert report["target"]["final_url"] == "https://example.com"
    assert report["target"]["status_code"] == 200
    assert report["target"]["response_time_ms"] == 42
    assert report["http"]["redirect_location"] == "https://example.com/redirected"
    assert report["http"]["server"] == "nginx"
    assert report["http"]["x_powered_by"] == "ExampleServer"
    assert report["security_headers"]["Content-Security-Policy"]["present"] is True
    assert report["cookies"][0]["secure"] is True
    assert report["cookies"][0]["http_only"] is True
    assert report["cookies"][0]["same_site"] == "Lax"
    assert any("Authorization reminder" in note for note in report["notes"])
