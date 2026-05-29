import re
from typing import Dict
from urllib.parse import urlparse

import tldextract

from app.models.parsed_email import ParsedEmail

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cli.gs", "pic.gd", "dlvr.it", "short.to", "lnkd.in", "fb.me", "adf.ly",
    "tiny.cc", "url4.eu", "twit.ac", "su.pr", "youtu.be", "cutt.ly",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "xyz", "top", "pw", "cc", "gq", "work",
    "date", "racing", "review", "cricket", "science", "party",
}

LOGIN_KEYWORDS = {"login", "signin", "sign-in", "verify", "account", "secure", "update", "confirm"}

_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)


def _is_ip_host(netloc: str) -> bool:
    host = netloc.split(":")[0]
    return bool(_IP_RE.match(host))


def _has_non_standard_port(netloc: str) -> bool:
    if ":" in netloc:
        _, port = netloc.rsplit(":", 1)
        try:
            p = int(port)
            return p not in (80, 443)
        except ValueError:
            pass
    return False


def extract_url_features(parsed: ParsedEmail) -> Dict[str, object]:
    urls = parsed.all_urls
    features: Dict[str, object] = {}

    features["total_urls"] = len(urls)

    num_ip = sum(1 for u in urls if _is_ip_host(urlparse(u).netloc))
    features["num_urls_with_ip"] = num_ip

    def _reg_domain(url: str) -> str:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ""

    num_short = sum(1 for u in urls if _reg_domain(u) in URL_SHORTENERS)
    features["num_url_shorteners"] = num_short

    mismatches = 0
    for link in parsed.urls_in_html:
        display = link.get("display_text", "")
        href = link.get("href", "")
        if re.match(r'https?://', display.strip()):
            d_host = urlparse(display.strip()).netloc.lower()
            h_host = urlparse(href).netloc.lower()
            if d_host and h_host and d_host != h_host:
                mismatches += 1
    features["num_display_href_mismatches"] = mismatches

    lengths = [len(u) for u in urls] if urls else [0]
    features["max_url_length"] = max(lengths)
    features["avg_url_length"] = round(sum(lengths) / len(lengths), 2) if urls else 0.0

    features["num_urls_with_at_symbol"] = sum(1 for u in urls if "@" in urlparse(u).netloc)

    features["num_urls_with_hex_encoding"] = sum(
        1 for u in urls if u.count("%") > 3
    )

    https_count = sum(1 for u in urls if u.lower().startswith("https://"))
    features["https_ratio"] = round(https_count / len(urls), 4) if urls else 1.0

    features["num_urls_with_port"] = sum(
        1 for u in urls if _has_non_standard_port(urlparse(u).netloc)
    )

    features["num_urls_with_suspicious_tld"] = sum(
        1 for u in urls if tldextract.extract(u).suffix.lower() in SUSPICIOUS_TLDS
    )

    features["num_urls_with_login_keyword"] = sum(
        1 for u in urls if any(kw in u.lower() for kw in LOGIN_KEYWORDS)
    )

    subdomain_depths = []
    for u in urls:
        ext = tldextract.extract(u)
        depth = len(ext.subdomain.split(".")) if ext.subdomain else 0
        subdomain_depths.append(depth)
    features["subdomain_depth_max"] = max(subdomain_depths) if subdomain_depths else 0

    return features
