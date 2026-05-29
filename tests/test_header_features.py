from app.services.email_parser import EmailParser
from app.features.header_features import extract_header_features


def _parse(raw: str):
    return EmailParser().parse(raw)


def test_reply_to_domain_mismatch():
    parsed = _parse(
        "From: legit@paypal.com\nReply-To: collect@evil.com\nSubject: test\n\nbody"
    )
    f = extract_header_features(parsed)
    assert f["from_replyto_domain_mismatch"] == 1
    assert f["reply_to_present"] == 1


def test_no_mismatch_when_same_domain():
    parsed = _parse(
        "From: user@paypal.com\nReply-To: support@paypal.com\nSubject: test\n\nbody"
    )
    f = extract_header_features(parsed)
    assert f["from_replyto_domain_mismatch"] == 0


def test_freemail_sender():
    parsed = _parse("From: user@gmail.com\nSubject: test\n\nbody")
    f = extract_header_features(parsed)
    assert f["sender_is_freemail"] == 1


def test_non_freemail_sender():
    parsed = _parse("From: user@enterprise.com\nSubject: test\n\nbody")
    f = extract_header_features(parsed)
    assert f["sender_is_freemail"] == 0


def test_fake_re_prefix():
    parsed = _parse("From: a@b.com\nSubject: Re: Important Notice\n\nbody")
    f = extract_header_features(parsed)
    assert f["subject_has_re_fw_prefix"] == 1


def test_real_reply_has_no_flag():
    parsed = _parse(
        "From: a@b.com\nSubject: Re: Important Notice\nIn-Reply-To: <123@b.com>\n\nbody"
    )
    f = extract_header_features(parsed)
    assert f["subject_has_re_fw_prefix"] == 0
