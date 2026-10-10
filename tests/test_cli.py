import json
import sys
from types import SimpleNamespace

import pytest

import checker
from websec import __version__
from websec.html_report import render_html_report
from websec.report import build_report


def test_render_html_report_escapes_report_values():
    report = build_report(
        input_url="https://example.test",
        final_url="https://example.test",
        status_code=200,
        response_time_ms=1,
        response_headers={
            "Server": '<script>alert("header")</script>',
            "Set-Cookie": 'session="<img src=x onerror=alert(1)>"',
        },
    )

    rendered = render_html_report(report)

    assert "&lt;script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert "<script>" not in rendered
    assert "<img" not in rendered


def test_version_option_exits_without_fetching(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["checker.py", "--version"])
    monkeypatch.setattr(checker, "fetch_url", lambda *args, **kwargs: pytest.fail("unexpected request"))

    with pytest.raises(SystemExit) as exit_info:
        checker.main()

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"checker.py {__version__}"


def test_cli_writes_json_and_html_from_one_mocked_response(tmp_path, monkeypatch, capsys):
    response = SimpleNamespace(
        url="https://example.test/",
        status_code=200,
        headers={"Server": "test-server"},
        raw=SimpleNamespace(headers={
            "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
        }),
    )
    calls = []

    def fake_fetch_url(url, *, timeout, follow_redirects):
        calls.append((url, timeout, follow_redirects))
        return response

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    monkeypatch.setattr(checker, "fetch_url", fake_fetch_url)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "checker.py",
            "inspect",
            "https://example.test",
            "--output",
            str(json_path),
            "--html-output",
            str(html_path),
        ],
    )

    assert checker.main() == 0
    stdout = capsys.readouterr().out
    file_report = json.loads(json_path.read_text(encoding="utf-8"))

    assert calls == [("https://example.test", 10.0, False)]
    assert "Inspection complete: https://example.test/" in stdout
    assert file_report["cookies"][0]["same_site"] == "Lax"
    assert "Web Security Inspection Report" in html_path.read_text(encoding="utf-8")


def test_check_returns_policy_mismatch_when_requested(tmp_path, monkeypatch, capsys):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"headers": {"x-content-type-options": {"required": True}}}),
        encoding="utf-8",
    )
    report = {
        "target": {"final_url": "https://example.test/"},
        "security_headers": {},
        "cookies": [],
    }
    monkeypatch.setattr(checker, "_inspect_report", lambda args: report)

    exit_code = checker.run(
        [
            "check",
            "https://example.test",
            "--policy",
            str(policy_path),
            "--fail-on-policy-mismatch",
        ]
    )

    assert exit_code == checker.EXIT_POLICY_MISMATCH
    assert (
        'Required header "x-content-type-options" was not observed.'
        in capsys.readouterr().out
    )


def test_check_returns_success_for_policy_mismatch_without_fail_flag(
    tmp_path, monkeypatch
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"headers": {"x-content-type-options": {"required": True}}}),
        encoding="utf-8",
    )
    report = {
        "target": {"final_url": "https://example.test/"},
        "security_headers": {},
        "cookies": [],
    }
    monkeypatch.setattr(checker, "_inspect_report", lambda args: report)

    exit_code = checker.run(
        ["check", "https://example.test", "--policy", str(policy_path)]
    )

    assert exit_code == checker.EXIT_SUCCESS


def test_compare_returns_error_for_invalid_json(tmp_path, capsys):
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{invalid json", encoding="utf-8")

    exit_code = checker.run(
        ["compare", str(invalid_path), str(invalid_path)]
    )

    assert exit_code == checker.EXIT_ERROR
    assert "Error:" in capsys.readouterr().err
