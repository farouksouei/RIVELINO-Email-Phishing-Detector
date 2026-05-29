from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ParsedEmail:
    raw: str
    subject: Optional[str] = None
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    to: Optional[str] = None
    date: Optional[str] = None
    received_headers: List[str] = field(default_factory=list)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls_in_text: List[str] = field(default_factory=list)
    urls_in_html: List[Dict] = field(default_factory=list)
    all_urls: List[str] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    authentication_results: Optional[str] = None
    spf_header: Optional[str] = None
    dkim_header: Optional[str] = None
