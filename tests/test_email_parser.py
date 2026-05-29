import pytest
from app.services.email_parser import EmailParser


@pytest.fixture
def parser():
    return EmailParser()


def test_parse_phishing_email(parser, phishing_email):
    parsed = parser.parse(phishing_email)
    assert parsed.sender_email is not None
    assert "paypa1-alerts.tk" in (parsed.sender_domain or "")
    assert parsed.reply_to is not None
    assert parsed.body_html is not None
    assert parsed.all_urls


def test_parse_legitimate_email(parser, legitimate_email):
    parsed = parser.parse(legitimate_email)
    assert parsed.sender_email == "noreply@github.com"
    assert parsed.sender_domain == "github.com"
    assert parsed.body_text is not None
    assert "https://github.com" in (parsed.body_text or "")


def test_parse_empty_email(parser):
    parsed = parser.parse("")
    assert parsed.raw == ""
    assert parsed.sender_email is None


def test_parse_body_only(parser):
    raw = "Hello, this is just a plain body without headers."
    parsed = parser.parse(raw)
    assert parsed.raw == raw


def test_url_extraction_from_text(parser):
    raw = """\
From: test@example.com
Subject: test

Visit https://example.com/login and http://evil.tk/page for more info.
"""
    parsed = parser.parse(raw)
    assert "https://example.com/login" in parsed.all_urls
    assert "http://evil.tk/page" in parsed.all_urls


def test_html_link_extraction(parser):
    raw = """\
From: test@example.com
Subject: test
Content-Type: text/html

<html><body>
<a href="http://evil.com/steal">Click here to verify your PayPal account</a>
</body></html>
"""
    parsed = parser.parse(raw)
    assert any(link["href"] == "http://evil.com/steal" for link in parsed.urls_in_html)
