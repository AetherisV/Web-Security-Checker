import pytest

from websec.validators import normalize_target_url


def test_normalize_target_url_adds_https_when_missing_scheme():
    assert normalize_target_url("example.com") == "https://example.com"


def test_normalize_target_url_strips_whitespace():
    assert normalize_target_url("  https://example.com/path  ") == "https://example.com/path"


def test_normalize_target_url_rejects_malformed_values():
    with pytest.raises(ValueError):
        normalize_target_url(" ")

    with pytest.raises(ValueError):
        normalize_target_url("not a url")

    with pytest.raises(ValueError):
        normalize_target_url("ftp://example.com")

    with pytest.raises(ValueError):
        normalize_target_url("https:///missing-host")
