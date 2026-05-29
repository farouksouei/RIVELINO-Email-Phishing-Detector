import re
from typing import Dict

from app.models.parsed_email import ParsedEmail

URGENCY_KEYWORDS = {
    "act now", "act immediately", "urgent", "immediately", "expire", "expires",
    "expiring", "suspended", "limited time", "verify now", "account locked",
    "account suspended", "your account", "click now", "respond immediately",
    "action required", "required immediately", "hours only", "24 hours",
    "last chance", "final notice", "important notice", "don't delay",
    "confirm now", "update now", "reactivate", "unauthorized", "security alert",
    "unusual activity", "suspicious activity", "validate", "immediately",
}

CREDENTIAL_KEYWORDS = {
    "password", "passwd", "passphrase", "pin", "credit card", "card number",
    "ssn", "social security", "bank account", "routing number", "cvv",
    "security code", "login credentials", "enter your", "provide your",
    "confirm your", "verify your identity",
}

FINANCIAL_KEYWORDS = {
    "bank", "account", "payment", "transfer", "wire", "invoice", "billing",
    "transaction", "refund", "reward", "prize", "winning", "lottery",
    "million dollars", "inheritance", "funds",
}

ACTION_PHRASES = {
    "click here", "click the link", "click below", "verify now", "update your",
    "sign in", "log in", "open attachment", "download now", "view document",
    "confirm your", "validate your", "unlock your account",
}

GENERIC_GREETINGS = re.compile(
    r'\b(dear\s+(customer|user|sir|madam|account\s*holder|valued\s*member|member|client))\b',
    re.IGNORECASE,
)

THREATENING = re.compile(
    r'\b(legal\s+action|police|arrest|lawsuit|sue\s+you|take\s+you\s+to\s+court|criminal\s+charges)\b',
    re.IGNORECASE,
)

BASIC_WORDS: set = set()

def _load_basic_words() -> set:
    global BASIC_WORDS
    if BASIC_WORDS:
        return BASIC_WORDS
    # Top ~2000 English words as a minimal spelling heuristic
    common = (
        "the be to of and a in that have it for on are with as you do at this but his by from "
        "they we say her she or an will my one all would there their what so up out if about who "
        "get which go me when make can like time no just him know take people into year your good "
        "some could them see other than then now look only come its over think also back after use "
        "two how our work first well way even new want because any these give day most us"
    ).split()
    BASIC_WORDS = set(common)
    return BASIC_WORDS


def _count_matches(text: str, keywords: set) -> int:
    text_lower = text.lower()
    return sum(1 for kw in keywords if kw in text_lower)


def extract_body_features(parsed: ParsedEmail) -> Dict[str, object]:
    text = parsed.body_text or ""
    html = parsed.body_html or ""
    features: Dict[str, object] = {}

    features["body_length"] = len(text)

    urgency_count = _count_matches(text, URGENCY_KEYWORDS)
    features["urgency_keyword_count"] = urgency_count

    words = re.findall(r'\b\w+\b', text)
    total_words = max(len(words), 1)
    features["urgency_keyword_density"] = round(urgency_count / total_words, 6)

    features["credential_request"] = int(
        _count_matches(text.lower(), CREDENTIAL_KEYWORDS) > 0
        or _count_matches(html.lower(), CREDENTIAL_KEYWORDS) > 0
    )

    features["financial_keyword_count"] = _count_matches(text, FINANCIAL_KEYWORDS)

    features["action_phrase_count"] = _count_matches(text, ACTION_PHRASES) + _count_matches(
        html, ACTION_PHRASES
    )

    features["contains_html_form"] = int(bool(re.search(r'<form[\s>]', html, re.IGNORECASE)))

    features["contains_html_input"] = int(
        bool(re.search(r'<input[\s>]', html, re.IGNORECASE))
    )

    hidden = (
        re.search(r'display\s*:\s*none', html, re.IGNORECASE)
        or re.search(r'font-size\s*:\s*0', html, re.IGNORECASE)
        or re.search(r'visibility\s*:\s*hidden', html, re.IGNORECASE)
        or re.search(r'color\s*:\s*#(?:fff(?:fff)?|ffffff)', html, re.IGNORECASE)
    )
    features["hidden_text_detected"] = int(bool(hidden))

    img_count = len(re.findall(r'<img[\s>]', html, re.IGNORECASE))
    features["image_to_text_ratio"] = round(img_count / max(len(text), 1), 6)

    features["greeting_is_generic"] = int(bool(GENERIC_GREETINGS.search(text)))

    features["contains_threatening_language"] = int(bool(THREATENING.search(text)))

    features["excessive_exclamation_marks"] = text.count("!")

    cap_words = sum(1 for w in words if w.isupper() and len(w) > 1)
    features["capitalized_word_ratio"] = round(cap_words / total_words, 6)

    basic = _load_basic_words()
    unknown = sum(1 for w in words if w.lower() not in basic and w.isalpha() and len(w) > 3)
    features["spelling_error_estimate"] = round(unknown / total_words, 6)

    return features
