import json
from pathlib import Path
from typing import Dict, List

import numpy as np

from app.features.auth_features import extract_auth_features
from app.features.body_features import extract_body_features
from app.features.header_features import extract_header_features
from app.features.structural_features import extract_structural_features
from app.features.url_features import extract_url_features
from app.models.parsed_email import ParsedEmail

FEATURE_ORDER: List[str] = [
    # Header (12)
    "from_display_domain_mismatch", "from_replyto_domain_mismatch", "reply_to_present",
    "num_received_headers", "received_chain_suspicious", "sender_is_freemail",
    "sender_has_subdomain", "x_mailer_suspicious", "subject_has_re_fw_prefix",
    "multiple_to_recipients", "header_encoding_anomaly", "date_header_mismatch",
    # URL (13)
    "total_urls", "num_urls_with_ip", "num_url_shorteners", "num_display_href_mismatches",
    "max_url_length", "avg_url_length", "num_urls_with_at_symbol", "num_urls_with_hex_encoding",
    "https_ratio", "num_urls_with_port", "num_urls_with_suspicious_tld",
    "num_urls_with_login_keyword", "subdomain_depth_max",
    # Body (15)
    "body_length", "urgency_keyword_count", "urgency_keyword_density", "credential_request",
    "financial_keyword_count", "action_phrase_count", "contains_html_form",
    "contains_html_input", "hidden_text_detected", "image_to_text_ratio",
    "greeting_is_generic", "contains_threatening_language", "excessive_exclamation_marks",
    "capitalized_word_ratio", "spelling_error_estimate",
    # Structural (8)
    "attachment_count", "has_dangerous_attachment", "dangerous_attachment_count",
    "has_double_extension", "mime_tree_depth", "num_base64_parts",
    "has_embedded_image", "content_type_mismatch",
    # Auth (4)
    "spf_pass", "dkim_pass", "dmarc_pass", "auth_score",
]


def extract_features(parsed: ParsedEmail) -> Dict[str, object]:
    features: Dict[str, object] = {}
    features.update(extract_header_features(parsed))
    features.update(extract_url_features(parsed))
    features.update(extract_body_features(parsed))
    features.update(extract_structural_features(parsed))
    features.update(extract_auth_features(parsed))
    return features


def features_to_vector(features: Dict[str, object], feature_order: List[str] = None) -> np.ndarray:
    order = feature_order or FEATURE_ORDER
    return np.array([float(features.get(name, 0)) for name in order], dtype=np.float64)


def save_feature_config(path: str = "training/feature_config.json") -> None:
    config = {
        "feature_names": FEATURE_ORDER,
        "num_features": len(FEATURE_ORDER),
        "groups": {
            "header": FEATURE_ORDER[:12],
            "url": FEATURE_ORDER[12:25],
            "body": FEATURE_ORDER[25:40],
            "structural": FEATURE_ORDER[40:48],
            "auth": FEATURE_ORDER[48:],
        },
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)


def load_feature_config(path: str) -> List[str]:
    with open(path) as f:
        return json.load(f)["feature_names"]
