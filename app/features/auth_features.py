import re
from typing import Dict

from app.models.parsed_email import ParsedEmail

_SPF_RE = re.compile(r'spf\s*=\s*(\w+)', re.IGNORECASE)
_DKIM_RE = re.compile(r'dkim\s*=\s*(\w+)', re.IGNORECASE)
_DMARC_RE = re.compile(r'dmarc\s*=\s*(\w+)', re.IGNORECASE)


def _parse_result(pattern: re.Pattern, text: str) -> int:
    match = pattern.search(text)
    if not match:
        return -1
    result = match.group(1).lower()
    if result == "pass":
        return 1
    if result in ("fail", "softfail", "none", "neutral", "temperror", "permerror"):
        return 0
    return -1


def extract_auth_features(parsed: ParsedEmail) -> Dict[str, int]:
    features: Dict[str, int] = {}

    auth_text = " ".join(filter(None, [
        parsed.authentication_results,
        parsed.spf_header,
        parsed.headers.get("received-spf"),
    ]))

    spf = _parse_result(_SPF_RE, auth_text)
    dkim = _parse_result(_DKIM_RE, auth_text)

    dmarc_text = auth_text
    if parsed.headers.get("dmarc"):
        dmarc_text += " " + parsed.headers["dmarc"]
    dmarc = _parse_result(_DMARC_RE, dmarc_text)

    if spf == -1 and parsed.spf_header:
        spf_lower = parsed.spf_header.lower()
        if "pass" in spf_lower:
            spf = 1
        elif any(w in spf_lower for w in ("fail", "softfail", "none")):
            spf = 0

    features["spf_pass"] = spf
    features["dkim_pass"] = dkim
    features["dmarc_pass"] = dmarc

    auth_score = sum(v for v in (spf, dkim, dmarc) if v != -1)
    features["auth_score"] = auth_score

    return features
