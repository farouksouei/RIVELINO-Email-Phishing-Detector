from typing import Dict, List

from app.models.parsed_email import ParsedEmail
from app.schemas.response import (
    AuthAnalysisResult,
    BodyAnalysisResult,
    FeatureBreakdown,
    FlaggedUrl,
    HeaderAnalysisResult,
    RiskFactor,
    StructuralAnalysisResult,
    UrlAnalysisResult,
)

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "from_display_domain_mismatch": "Display name suggests a different organization than the actual sender domain",
    "from_replyto_domain_mismatch": "Replies would go to a different domain than the sender",
    "reply_to_present": "Email has a Reply-To header redirecting responses elsewhere",
    "num_received_headers": "Number of mail server hops the email passed through",
    "received_chain_suspicious": "Received header chain contains suspicious routing",
    "sender_is_freemail": "Sender is using a free webmail provider",
    "sender_has_subdomain": "Sender domain includes subdomains (may spoof trusted brands)",
    "x_mailer_suspicious": "X-Mailer header is absent or matches known bulk/spam tools",
    "subject_has_re_fw_prefix": "Subject has Re:/Fw: prefix but no matching In-Reply-To header (fake thread)",
    "multiple_to_recipients": "Email was sent to multiple recipients (mass mailing indicator)",
    "header_encoding_anomaly": "Headers use unusual character encodings",
    "date_header_mismatch": "Date header differs significantly from actual received timestamps",
    "total_urls": "Total number of unique URLs found in the email",
    "num_urls_with_ip": "URLs use raw IP addresses instead of domain names",
    "num_url_shorteners": "URLs use link-shortening services that hide the real destination",
    "num_display_href_mismatches": "Some links display one URL but actually point somewhere else",
    "max_url_length": "Maximum URL length (very long URLs can hide malicious intent)",
    "avg_url_length": "Average URL length",
    "num_urls_with_at_symbol": "URLs contain @ symbol (can be used to disguise the real host)",
    "num_urls_with_hex_encoding": "URLs contain excessive percent-encoding to obfuscate content",
    "https_ratio": "Fraction of URLs using HTTPS (lower values are suspicious)",
    "num_urls_with_port": "URLs specify non-standard ports",
    "num_urls_with_suspicious_tld": "URLs use top-level domains frequently associated with abuse",
    "num_urls_with_login_keyword": "URLs contain login/verify/account keywords",
    "subdomain_depth_max": "Maximum subdomain depth across all URLs (deep subdomains are suspicious)",
    "body_length": "Length of the email body",
    "urgency_keyword_count": "Count of urgency-inducing phrases",
    "urgency_keyword_density": "The email uses an unusual density of urgent language",
    "credential_request": "The email asks for sensitive information like passwords or account numbers",
    "financial_keyword_count": "Count of financial/monetary keywords",
    "action_phrase_count": "Count of call-to-action phrases pushing the reader to click or act",
    "contains_html_form": "The email HTML body contains a form element (credential harvesting)",
    "contains_html_input": "The email HTML contains input fields",
    "hidden_text_detected": "The email contains hidden text (used to fool spam filters)",
    "image_to_text_ratio": "High image-to-text ratio (images used to hide text from filters)",
    "greeting_is_generic": "Greeting is generic (Dear Customer/User) rather than personalised",
    "contains_threatening_language": "Email contains threatening language (legal action, arrest, etc.)",
    "excessive_exclamation_marks": "Email uses an excessive number of exclamation marks",
    "capitalized_word_ratio": "Unusually high proportion of words in ALL CAPS",
    "spelling_error_estimate": "High estimated rate of spelling errors",
    "attachment_count": "Number of file attachments",
    "has_dangerous_attachment": "Email contains attachments with potentially dangerous file types",
    "dangerous_attachment_count": "Count of dangerous-extension attachments",
    "has_double_extension": "Attachment has a double extension (e.g. invoice.pdf.exe)",
    "mime_tree_depth": "MIME structure complexity",
    "num_base64_parts": "Number of base64-encoded MIME parts",
    "has_embedded_image": "Email embeds images as inline MIME parts",
    "content_type_mismatch": "Declared content type does not match actual content",
    "spf_pass": "SPF email authentication result",
    "dkim_pass": "DKIM email authentication result",
    "dmarc_pass": "DMARC email authentication result",
    "auth_score": "Combined email authentication score (SPF + DKIM + DMARC)",
}


class Explainer:
    def __init__(self, model, feature_names: list):
        self.model = model
        self.feature_names = feature_names
        self._importances = dict(zip(feature_names, model.feature_importances_.tolist()))

    def top_risk_factors(
        self,
        features: Dict[str, object],
        n: int = 5,
    ) -> List[RiskFactor]:
        contributions = []
        for name in self.feature_names:
            value = float(features.get(name, 0))
            importance = self._importances.get(name, 0.0)
            contribution = importance * abs(value)
            contributions.append((name, value, contribution))

        contributions.sort(key=lambda x: x[2], reverse=True)

        return [
            RiskFactor(
                feature_name=name,
                description=FEATURE_DESCRIPTIONS.get(name, name),
                value=value,
                risk_contribution=round(contrib, 6),
            )
            for name, value, contrib in contributions[:n]
        ]

    def build_breakdown(self, parsed: ParsedEmail, features: Dict, result) -> FeatureBreakdown:
        return FeatureBreakdown(
            header_analysis=self._header_analysis(parsed, features),
            url_analysis=self._url_analysis(parsed, features),
            body_analysis=self._body_analysis(features),
            structural_analysis=self._structural_analysis(features),
            auth_analysis=self._auth_analysis(features),
            top_risk_factors=self.top_risk_factors(features),
        )

    @staticmethod
    def _header_analysis(parsed: ParsedEmail, f: Dict) -> HeaderAnalysisResult:
        flags = []
        if f.get("from_display_domain_mismatch"):
            flags.append("Display name domain mismatch")
        if f.get("from_replyto_domain_mismatch"):
            flags.append("Reply-To domain mismatch")
        if f.get("subject_has_re_fw_prefix"):
            flags.append("Fake Re:/Fw: thread")
        if f.get("sender_is_freemail"):
            flags.append("Sender uses free webmail")
        return HeaderAnalysisResult(
            sender_display_name=parsed.sender_name,
            sender_email=parsed.sender_email,
            sender_domain=parsed.sender_domain,
            reply_to_domain=parsed.reply_to_domain,
            from_replyto_mismatch=bool(f.get("from_replyto_domain_mismatch")),
            display_name_email_mismatch=bool(f.get("from_display_domain_mismatch")),
            suspicious_received_chain=bool(f.get("received_chain_suspicious")),
            num_received_headers=int(f.get("num_received_headers", 0)),
            flags=flags,
        )

    @staticmethod
    def _url_analysis(parsed: ParsedEmail, f: Dict) -> UrlAnalysisResult:
        flagged = []
        for link in parsed.urls_in_html:
            href = link.get("href", "")
            display = link.get("display_text", "")
            if href and display and href != display:
                import re
                if re.match(r'https?://', display.strip()):
                    flagged.append(FlaggedUrl(url=href, reason="Display text URL differs from href"))
        for url in parsed.all_urls:
            if "@" in url:
                flagged.append(FlaggedUrl(url=url, reason="Contains @ symbol"))

        total = int(f.get("total_urls", 0))
        suspicious = int(f.get("num_urls_with_ip", 0)) + int(f.get("num_url_shorteners", 0))

        return UrlAnalysisResult(
            total_urls=total,
            suspicious_urls=suspicious,
            urls_with_ip_address=int(f.get("num_urls_with_ip", 0)),
            url_shorteners_count=int(f.get("num_url_shorteners", 0)),
            display_href_mismatches=int(f.get("num_display_href_mismatches", 0)),
            https_ratio=float(f.get("https_ratio", 1.0)),
            longest_url_length=int(f.get("max_url_length", 0)),
            flagged_urls=flagged[:10],
        )

    @staticmethod
    def _body_analysis(f: Dict) -> BodyAnalysisResult:
        flags = []
        if f.get("credential_request"):
            flags.append("Requests sensitive credentials")
        if f.get("contains_html_form"):
            flags.append("Contains HTML form")
        if f.get("hidden_text_detected"):
            flags.append("Contains hidden text")
        if f.get("greeting_is_generic"):
            flags.append("Generic greeting")
        if f.get("contains_threatening_language"):
            flags.append("Threatening language")

        return BodyAnalysisResult(
            urgency_score=float(f.get("urgency_keyword_density", 0.0)),
            credential_request_detected=bool(f.get("credential_request")),
            contains_html_form=bool(f.get("contains_html_form")),
            hidden_text_detected=bool(f.get("hidden_text_detected")),
            body_length=int(f.get("body_length", 0)),
            grammar_error_estimate=float(f.get("spelling_error_estimate", 0.0)),
            flags=flags,
        )

    @staticmethod
    def _structural_analysis(f: Dict) -> StructuralAnalysisResult:
        flags = []
        if f.get("has_dangerous_attachment"):
            flags.append("Dangerous attachment type detected")
        if f.get("has_double_extension"):
            flags.append("Double file extension in attachment")
        return StructuralAnalysisResult(
            has_attachments=int(f.get("attachment_count", 0)) > 0,
            attachment_count=int(f.get("attachment_count", 0)),
            has_embedded_images=bool(f.get("has_embedded_image")),
            multipart_complexity=int(f.get("mime_tree_depth", 0)),
            base64_encoded_parts=int(f.get("num_base64_parts", 0)),
            flags=flags,
        )

    @staticmethod
    def _auth_analysis(f: Dict) -> AuthAnalysisResult:
        spf = f.get("spf_pass", -1)
        dkim = f.get("dkim_pass", -1)
        dmarc = f.get("dmarc_pass", -1)

        results = [v for v in (spf, dkim, dmarc) if v != -1]
        if not results:
            summary = "not_available"
        elif all(v == 1 for v in results):
            summary = "all_pass"
        elif all(v == 0 for v in results):
            summary = "all_fail"
        else:
            summary = "partial_fail"

        flags = []
        if spf == 0:
            flags.append("SPF failed")
        if dkim == 0:
            flags.append("DKIM failed")
        if dmarc == 0:
            flags.append("DMARC failed")

        return AuthAnalysisResult(
            spf_pass=None if spf == -1 else bool(spf),
            dkim_pass=None if dkim == -1 else bool(dkim),
            dmarc_pass=None if dmarc == -1 else bool(dmarc),
            auth_summary=summary,
            flags=flags,
        )
