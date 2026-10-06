from websec.report import _parse_cookie_headers, build_report


class RawHeaders:
    def __init__(self, values):
        self.values = values

    def getlist(self, name):
        assert name == "Set-Cookie"
        return self.values


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


def test_parse_cookie_headers_reads_repeated_raw_set_cookie_fields():
    cookies = _parse_cookie_headers(RawHeaders([
        "session=abc; Secure; HttpOnly; SameSite=Lax",
        "theme=light; SameSite=None",
    ]))

    assert [cookie["name"] for cookie in cookies] == ["session", "theme"]
    assert cookies[0]["secure"] is True
    assert cookies[0]["http_only"] is True
    assert cookies[0]["same_site"] == "Lax"
    assert cookies[1]["secure"] is False
    assert cookies[1]["http_only"] is False
    assert cookies[1]["same_site"] == "None"


def test_parse_cookie_headers_does_not_split_expires_date_in_combined_field():
    cookies = _parse_cookie_headers({
        "Set-Cookie": "first=1; Expires=Wed, 21 Oct 2030 07:28:00 GMT, second=2; HttpOnly"
    })

    assert [cookie["name"] for cookie in cookies] == ["first", "second"]
    assert cookies[0]["secure"] is False
    assert cookies[0]["http_only"] is False
    assert cookies[1]["http_only"] is True


def test_parse_cookie_headers_does_not_split_quoted_cookie_value():
    cookies = _parse_cookie_headers({
        "Set-Cookie": 'first="one, second=still-first"; Secure, second=2; HttpOnly'
    })

    assert [cookie["name"] for cookie in cookies] == ["first", "second"]
    assert cookies[0]["value"] == '"one, second=still-first"'
    assert cookies[0]["secure"] is True
    assert cookies[1]["http_only"] is True


def test_parse_cookie_headers_preserves_quoted_semicolons_and_cookie_values():
    cookies = _parse_cookie_headers({
        "Set-Cookie": 'token="one;two=three"; sEcUrE; samesite=Strict'
    })

    assert len(cookies) == 1
    assert cookies[0]["value"] == '"one;two=three"'
    assert cookies[0]["secure"] is True
    assert cookies[0]["same_site"] == "Strict"


def test_parse_cookie_headers_reports_malformed_attributes_as_unknown():
    cookies = _parse_cookie_headers({
        "Set-Cookie": "session=abc; Secure=yes; HttpOnly; SameSite="
    })

    assert len(cookies) == 1
    assert cookies[0]["secure"] is None
    assert cookies[0]["http_only"] is True
    assert cookies[0]["same_site"] is None


def test_parse_cookie_headers_skips_malformed_cookie_names():
    assert _parse_cookie_headers({"Set-Cookie": "not a name=value; Secure"}) == []
