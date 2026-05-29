import email
import email.utils
import re
from email import policy
from email.header import decode_header
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

import tldextract

from app.models.parsed_email import ParsedEmail

_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
_MAX_BODY_CHARS = 100_000


def _decode_header_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def _extract_domain(email_address: Optional[str]) -> Optional[str]:
    if not email_address:
        return None
    _, addr = email.utils.parseaddr(email_address)
    if "@" not in addr:
        return None
    domain = addr.split("@", 1)[1].lower()
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain or None


class _AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[Dict] = []
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            attrs_dict = dict(attrs)
            self._current_href = attrs_dict.get("href")
            self._current_text = []

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href:
            self.links.append(
                {"display_text": "".join(self._current_text).strip(), "href": self._current_href}
            )
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)


def _extract_html_links(html: str) -> List[Dict]:
    parser = _AnchorParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.links


def _extract_urls_from_text(text: str) -> List[str]:
    return _URL_RE.findall(text)


def _get_mime_depth(msg, depth: int = 0) -> int:
    if msg.is_multipart():
        return max((_get_mime_depth(part, depth + 1) for part in msg.iter_parts()), default=depth)
    return depth


class EmailParser:
    def parse(self, raw: str) -> ParsedEmail:
        raw = raw.strip()
        if not raw:
            return ParsedEmail(raw=raw)

        try:
            msg = email.message_from_string(raw, policy=policy.compat32)
        except Exception:
            return ParsedEmail(raw=raw, body_text=raw[:_MAX_BODY_CHARS])

        headers: Dict[str, str] = {}
        for key in msg.keys():
            headers[key.lower()] = _decode_header_value(msg[key]) or ""

        subject = _decode_header_value(msg.get("Subject"))
        from_raw = _decode_header_value(msg.get("From")) or ""
        sender_name, sender_addr = email.utils.parseaddr(from_raw)
        sender_name = sender_name.strip() or None
        sender_email_addr = sender_addr.strip() or None
        sender_domain = _extract_domain(sender_addr)

        reply_to_raw = _decode_header_value(msg.get("Reply-To"))
        _, reply_to_addr = email.utils.parseaddr(reply_to_raw or "")
        reply_to = reply_to_addr.strip() or None
        reply_to_domain = _extract_domain(reply_to_addr) if reply_to else None

        to_raw = _decode_header_value(msg.get("To"))
        date_raw = _decode_header_value(msg.get("Date"))

        received_headers: List[str] = [
            _decode_header_value(v) or "" for v in msg.get_all("Received") or []
        ]

        authentication_results = _decode_header_value(msg.get("Authentication-Results"))
        spf_header = _decode_header_value(msg.get("Received-SPF"))
        dkim_header = _decode_header_value(msg.get("DKIM-Signature"))

        body_text: Optional[str] = None
        body_html: Optional[str] = None
        attachments: List[Dict] = []
        num_base64 = 0

        for part in msg.walk():
            ct = part.get_content_type()
            cd = part.get("Content-Disposition", "")
            cte = (part.get("Content-Transfer-Encoding") or "").lower()

            if cte == "base64":
                num_base64 += 1

            filename = part.get_filename()
            is_attachment = "attachment" in cd.lower() or (
                filename and ct not in ("text/plain", "text/html")
            )

            if is_attachment:
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    {
                        "filename": _decode_header_value(filename) or "unknown",
                        "content_type": ct,
                        "size": len(payload),
                    }
                )
                continue

            if ct == "text/plain" and body_text is None:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_text = payload.decode(charset, errors="replace")[:_MAX_BODY_CHARS]

            elif ct == "text/html" and body_html is None:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_html = payload.decode(charset, errors="replace")[:_MAX_BODY_CHARS]

        urls_in_text = _extract_urls_from_text(body_text or "")
        urls_in_html = _extract_html_links(body_html or "")
        href_urls = [link["href"] for link in urls_in_html if link.get("href", "").startswith("http")]
        all_urls = list(dict.fromkeys(urls_in_text + href_urls))

        return ParsedEmail(
            raw=raw,
            subject=subject,
            sender_name=sender_name,
            sender_email=sender_email_addr,
            sender_domain=sender_domain,
            reply_to=reply_to,
            reply_to_domain=reply_to_domain,
            to=to_raw,
            date=date_raw,
            received_headers=received_headers,
            body_text=body_text,
            body_html=body_html,
            urls_in_text=urls_in_text,
            urls_in_html=urls_in_html,
            all_urls=all_urls,
            attachments=attachments,
            headers=headers,
            authentication_results=authentication_results,
            spf_header=spf_header,
            dkim_header=dkim_header,
        )
