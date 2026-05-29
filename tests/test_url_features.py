from app.services.email_parser import EmailParser
from app.features.url_features import extract_url_features


def _parsed_with_urls(urls: list, html_links: list = None):
    from app.models.parsed_email import ParsedEmail
    return ParsedEmail(
        raw="",
        all_urls=urls,
        urls_in_text=urls,
        urls_in_html=html_links or [],
    )


def test_ip_url_detection():
    parsed = _parsed_with_urls(["http://192.168.1.1/login"])
    f = extract_url_features(parsed)
    assert f["num_urls_with_ip"] == 1


def test_shortener_detection():
    parsed = _parsed_with_urls(["https://bit.ly/3xABCD"])
    f = extract_url_features(parsed)
    assert f["num_url_shorteners"] == 1


def test_suspicious_tld():
    parsed = _parsed_with_urls(["http://malware.tk/payload"])
    f = extract_url_features(parsed)
    assert f["num_urls_with_suspicious_tld"] == 1


def test_https_ratio_all_https():
    parsed = _parsed_with_urls(["https://good.com/page", "https://also.com/safe"])
    f = extract_url_features(parsed)
    assert f["https_ratio"] == 1.0


def test_https_ratio_mixed():
    parsed = _parsed_with_urls(["https://good.com", "http://bad.com"])
    f = extract_url_features(parsed)
    assert f["https_ratio"] == 0.5


def test_display_href_mismatch():
    parsed = _parsed_with_urls(
        ["http://evil.com/steal"],
        html_links=[{"href": "http://evil.com/steal", "display_text": "http://paypal.com"}],
    )
    f = extract_url_features(parsed)
    assert f["num_display_href_mismatches"] == 1


def test_login_keyword_in_url():
    parsed = _parsed_with_urls(["http://example.com/login?user=test"])
    f = extract_url_features(parsed)
    assert f["num_urls_with_login_keyword"] == 1
