from app.models.parsed_email import ParsedEmail
from app.features.structural_features import extract_structural_features


def _parsed(attachments=None, raw="", html=""):
    return ParsedEmail(raw=raw, attachments=attachments or [], body_html=html)


def test_no_attachments():
    f = extract_structural_features(_parsed())
    assert f["attachment_count"] == 0
    assert f["has_dangerous_attachment"] == 0


def test_dangerous_exe_attachment():
    parsed = _parsed(attachments=[{"filename": "invoice.exe", "content_type": "application/octet-stream", "size": 1024}])
    f = extract_structural_features(parsed)
    assert f["has_dangerous_attachment"] == 1
    assert f["dangerous_attachment_count"] == 1


def test_double_extension_attachment():
    parsed = _parsed(attachments=[{"filename": "document.pdf.exe", "content_type": "application/octet-stream", "size": 512}])
    f = extract_structural_features(parsed)
    assert f["has_double_extension"] == 1


def test_safe_pdf_attachment():
    parsed = _parsed(attachments=[{"filename": "report.pdf", "content_type": "application/pdf", "size": 4096}])
    f = extract_structural_features(parsed)
    assert f["has_dangerous_attachment"] == 0
    assert f["has_double_extension"] == 0
