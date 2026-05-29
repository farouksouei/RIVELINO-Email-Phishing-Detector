from app.models.parsed_email import ParsedEmail
from app.features.body_features import extract_body_features


def _parsed(text="", html=""):
    return ParsedEmail(raw="", body_text=text, body_html=html)


def test_credential_request_detected():
    parsed = _parsed(text="Please enter your password and credit card number to verify.")
    f = extract_body_features(parsed)
    assert f["credential_request"] == 1


def test_no_credential_request():
    parsed = _parsed(text="Welcome to our newsletter. Enjoy the latest updates.")
    f = extract_body_features(parsed)
    assert f["credential_request"] == 0


def test_urgency_keywords():
    parsed = _parsed(text="Act now! Your account has been suspended immediately!")
    f = extract_body_features(parsed)
    assert f["urgency_keyword_count"] > 0


def test_html_form_detection():
    parsed = _parsed(html='<form action="/steal"><input type="password"></form>')
    f = extract_body_features(parsed)
    assert f["contains_html_form"] == 1
    assert f["contains_html_input"] == 1


def test_hidden_text():
    parsed = _parsed(html='<span style="display:none">invisible text</span>')
    f = extract_body_features(parsed)
    assert f["hidden_text_detected"] == 1


def test_generic_greeting():
    parsed = _parsed(text="Dear Customer, your account requires attention.")
    f = extract_body_features(parsed)
    assert f["greeting_is_generic"] == 1


def test_threatening_language():
    parsed = _parsed(text="Failure to comply will result in legal action and police involvement.")
    f = extract_body_features(parsed)
    assert f["contains_threatening_language"] == 1
