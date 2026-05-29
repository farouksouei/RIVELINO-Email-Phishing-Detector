import email.utils
import re
from typing import Dict

import tldextract

from app.models.parsed_email import ParsedEmail

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "yandex.com",
    "gmx.com", "zoho.com", "tutanota.com", "fastmail.com", "inbox.com",
    "rediffmail.com", "lycos.com", "excite.com", "msn.com", "me.com",
    "mac.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "live.co.uk", "windowslive.com",
}

SUSPICIOUS_MAILERS = {
    "phpmailer", "sendblaster", "massmailer", "bulk", "blaster", "spammer",
}


def _registered_domain(raw: str) -> str:
    ext = tldextract.extract(raw.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return raw.lower()


def _display_domain(display_name: str) -> str:
    match = re.search(r'[\w.-]+\.[a-z]{2,}', display_name, re.IGNORECASE)
    if match:
        return _registered_domain(match.group())
    return ""


def extract_header_features(parsed: ParsedEmail) -> Dict[str, int]:
    features: Dict[str, int] = {}

    sender_reg = _registered_domain(parsed.sender_domain or "")
    disp_domain = _display_domain(parsed.sender_name or "")
    features["from_display_domain_mismatch"] = int(
        bool(disp_domain) and disp_domain != sender_reg
    )

    reply_reg = _registered_domain(parsed.reply_to_domain or "")
    features["from_replyto_domain_mismatch"] = int(
        bool(parsed.reply_to) and bool(sender_reg) and reply_reg != sender_reg
    )

    features["reply_to_present"] = int(bool(parsed.reply_to))

    features["num_received_headers"] = len(parsed.received_headers)

    features["received_chain_suspicious"] = _check_received_chain(parsed.received_headers)

    features["sender_is_freemail"] = int(
        (parsed.sender_domain or "").lower() in FREEMAIL_DOMAINS
    )

    subdomain_levels = 0
    if parsed.sender_domain:
        ext = tldextract.extract(parsed.sender_domain)
        subdomain_levels = len(ext.subdomain.split(".")) if ext.subdomain else 0
    features["sender_has_subdomain"] = int(subdomain_levels > 0)

    x_mailer = (parsed.headers.get("x-mailer") or "").lower()
    features["x_mailer_suspicious"] = int(
        not x_mailer or any(s in x_mailer for s in SUSPICIOUS_MAILERS)
    )

    subject = (parsed.subject or "").strip()
    has_re_fw = bool(re.match(r'^(re:|fw:|fwd:)', subject, re.IGNORECASE))
    has_in_reply_to = bool(parsed.headers.get("in-reply-to"))
    features["subject_has_re_fw_prefix"] = int(has_re_fw and not has_in_reply_to)

    to_raw = parsed.to or ""
    cc_raw = parsed.headers.get("cc") or ""
    to_addrs = email.utils.getaddresses([to_raw, cc_raw])
    features["multiple_to_recipients"] = len(to_addrs)

    features["header_encoding_anomaly"] = _check_encoding_anomaly(parsed.headers)

    features["date_header_mismatch"] = _check_date_mismatch(
        parsed.headers.get("date") or "", parsed.received_headers
    )

    return features


def _check_received_chain(received: list) -> int:
    ip_pattern = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    for header in received:
        ips.extend(ip_pattern.findall(header))
    private_ranges = [
        re.compile(r'^10\.'), re.compile(r'^192\.168\.'), re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    ]
    public_count = sum(
        1 for ip in ips if not any(p.match(ip) for p in private_ranges)
    )
    return int(public_count > 3)


def _check_encoding_anomaly(headers: dict) -> int:
    unusual_charsets = {"koi8-r", "windows-1251", "iso-8859-5", "big5", "gb2312"}
    for key in ("subject", "from", "to"):
        val = headers.get(key, "")
        if any(cs in val.lower() for cs in unusual_charsets):
            return 1
    return 0


def _check_date_mismatch(date_header: str, received_headers: list) -> int:
    if not date_header or not received_headers:
        return 0
    try:
        import email.utils as eu
        date_ts = eu.parsedate_to_datetime(date_header).timestamp()
        for recv in received_headers[:2]:
            match = re.search(r';\s*(.+)$', recv)
            if match:
                recv_ts = eu.parsedate_to_datetime(match.group(1).strip()).timestamp()
                if abs(date_ts - recv_ts) > 86400:
                    return 1
    except Exception:
        pass
    return 0
