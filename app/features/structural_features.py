import re
from typing import Dict

from app.models.parsed_email import ParsedEmail

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".msi",
    ".com", ".pif", ".hta", ".wsf", ".zip", ".rar", ".7z", ".iso",
}

_DOUBLE_EXT_RE = re.compile(r'\.\w{2,4}\.\w{2,4}$')


def extract_structural_features(parsed: ParsedEmail) -> Dict[str, int]:
    features: Dict[str, int] = {}
    attachments = parsed.attachments or []

    features["attachment_count"] = len(attachments)

    dangerous = [
        a for a in attachments
        if any(a.get("filename", "").lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    ]
    features["has_dangerous_attachment"] = int(bool(dangerous))
    features["dangerous_attachment_count"] = len(dangerous)

    features["has_double_extension"] = int(
        any(_DOUBLE_EXT_RE.search(a.get("filename", "")) for a in attachments)
    )

    features["mime_tree_depth"] = _compute_mime_depth(parsed.raw)

    features["num_base64_parts"] = _count_base64_parts(parsed.raw)

    html = parsed.body_html or ""
    features["has_embedded_image"] = int(
        bool(re.search(r'<img\s[^>]*src=["\']cid:', html, re.IGNORECASE))
        or _has_inline_image_attachment(attachments)
    )

    features["content_type_mismatch"] = _check_content_type_mismatch(parsed)

    return features


def _compute_mime_depth(raw: str) -> int:
    import email as email_lib
    try:
        msg = email_lib.message_from_string(raw)
        return _walk_depth(msg, 0)
    except Exception:
        return 0


def _walk_depth(msg, depth: int) -> int:
    if msg.is_multipart():
        return max((_walk_depth(part, depth + 1) for part in msg.get_payload()), default=depth)
    return depth


def _count_base64_parts(raw: str) -> int:
    import email as email_lib
    count = 0
    try:
        msg = email_lib.message_from_string(raw)
        for part in msg.walk():
            cte = (part.get("Content-Transfer-Encoding") or "").lower()
            if cte == "base64":
                count += 1
    except Exception:
        pass
    return count


def _has_inline_image_attachment(attachments: list) -> bool:
    image_types = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}
    return any(a.get("content_type", "").lower() in image_types for a in attachments)


def _check_content_type_mismatch(parsed: ParsedEmail) -> int:
    if parsed.body_html and not parsed.body_text:
        ct = (parsed.headers.get("content-type") or "").lower()
        if "text/plain" in ct:
            return 1
    return 0
