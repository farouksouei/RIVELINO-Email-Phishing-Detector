from app.models.parsed_email import ParsedEmail
from app.features.auth_features import extract_auth_features


def _parsed(auth_results=None, spf_header=None):
    return ParsedEmail(raw="", authentication_results=auth_results, spf_header=spf_header)


def test_all_pass():
    parsed = _parsed(auth_results="mx.example.com; spf=pass; dkim=pass; dmarc=pass")
    f = extract_auth_features(parsed)
    assert f["spf_pass"] == 1
    assert f["dkim_pass"] == 1
    assert f["dmarc_pass"] == 1
    assert f["auth_score"] == 3


def test_all_fail():
    parsed = _parsed(auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=fail")
    f = extract_auth_features(parsed)
    assert f["spf_pass"] == 0
    assert f["dkim_pass"] == 0
    assert f["dmarc_pass"] == 0
    assert f["auth_score"] == 0


def test_no_auth_headers():
    parsed = _parsed()
    f = extract_auth_features(parsed)
    assert f["spf_pass"] == -1
    assert f["dkim_pass"] == -1
    assert f["dmarc_pass"] == -1
    assert f["auth_score"] == 0


def test_spf_from_received_spf():
    parsed = _parsed(spf_header="pass (sender is authorized)")
    f = extract_auth_features(parsed)
    assert f["spf_pass"] == 1
