from websec.policy import evaluate_policy


def report(headers=None, cookies=None):
    return {
        "security_headers": headers or {},
        "cookies": cookies or [],
    }


def header(value, observations=None, present=True):
    return {
        "present": present,
        "value": value,
        "observations": observations or {},
    }


def test_policy_matches_expected_configuration():
    source = report(
        headers={
            "strict-transport-security": header(
                "max-age=31536000; includeSubDomains",
                {"max_age": 31536000, "include_subdomains": True},
            ),
            "x-content-type-options": header("nosniff"),
            "referrer-policy": header("no-referrer"),
        },
        cookies=[{"name": "session", "secure": True, "httponly": True, "samesite": "Lax"}],
    )
    policy = {
        "policy_version": "1.0",
        "headers": {
            "strict-transport-security": {
                "required": True,
                "min_max_age": 31536000,
                "require_include_subdomains": True,
            },
            "x-content-type-options": {"required": True, "expected_value": "nosniff"},
            "referrer-policy": {"allowed_values": ["no-referrer"]},
        },
        "cookies": {
            "session_cookie_names": ["session"],
            "require_secure": True,
            "require_httponly": True,
            "require_samesite": True,
        },
    }

    result = evaluate_policy(source, policy)

    assert result["matched"] is True
    assert result["mismatches"] == []


def test_policy_reports_missing_and_non_matching_values():
    source = report(
        headers={
            "strict-transport-security": header(
                "max-age=3600",
                {"max_age": 3600, "include_subdomains": False},
            ),
            "referrer-policy": header("unsafe-url"),
        },
        cookies=[{"name": "session", "secure": False, "httponly": False, "samesite": None}],
    )
    policy = {
        "headers": {
            "strict-transport-security": {
                "min_max_age": 31536000,
                "require_include_subdomains": True,
            },
            "x-content-type-options": {"required": True, "expected_value": "nosniff"},
            "referrer-policy": {"allowed_values": ["no-referrer"]},
        },
        "cookies": {
            "session_cookie_names": ["session"],
            "require_secure": True,
            "require_httponly": True,
            "require_samesite": True,
        },
    }

    result = evaluate_policy(source, policy)

    assert result["matched"] is False
    messages = [item["message"] for item in result["mismatches"]]
    assert 'HSTS max-age was 3600; policy requires at least 31536000.' in messages
    assert 'HSTS did not include "includeSubDomains" as required by policy.' in messages
    assert 'Required header "x-content-type-options" was not observed.' in messages
    assert 'Header "referrer-policy" was "unsafe-url"; it is not allowed by policy.' in messages
    assert 'Cookie "session" was observed without Secure.' in messages
    assert 'Cookie "session" was observed without HttpOnly.' in messages
    assert 'Cookie "session" was observed without SameSite.' in messages


def test_policy_reports_missing_named_session_cookie():
    result = evaluate_policy(
        report(),
        {"cookies": {"session_cookie_names": ["session"]}},
    )

    assert result["matched"] is False
    assert result["mismatches"] == [
        {
            "subject": "cookie",
            "message": 'Required session cookie "session" was not observed.',
        }
    ]
