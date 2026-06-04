from typing import Any, List, Optional

from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    feature_name: str = Field(..., description="Internal feature identifier (snake_case).")
    description: str = Field(..., description="Human-readable explanation of what this feature measures.")
    value: Any = Field(..., description="The extracted value of the feature for this email.")
    risk_contribution: float = Field(
        ...,
        description="Normalised importance score (0–1) representing how much this feature pushed the prediction toward phishing.",
        ge=0.0,
        le=1.0,
    )


class HeaderAnalysisResult(BaseModel):
    sender_display_name: Optional[str] = Field(None, description="Display name extracted from the From header.")
    sender_email: Optional[str] = Field(None, description="Email address extracted from the From header.")
    sender_domain: Optional[str] = Field(None, description="Registered domain of the sender.")
    reply_to_domain: Optional[str] = Field(None, description="Registered domain of the Reply-To address, if present.")
    from_replyto_mismatch: bool = Field(False, description="True if the Reply-To domain differs from the From domain.")
    display_name_email_mismatch: bool = Field(False, description="True if the display name contains a domain that differs from the actual sender domain.")
    suspicious_received_chain: bool = Field(False, description="True if the Received header chain contains more than 3 public IP addresses.")
    spf_result: Optional[str] = Field(None, description="Raw SPF result string from the Authentication-Results header.")
    dkim_result: Optional[str] = Field(None, description="Raw DKIM result string from the Authentication-Results header.")
    dmarc_result: Optional[str] = Field(None, description="Raw DMARC result string from the Authentication-Results header.")
    num_received_headers: int = Field(0, description="Count of Received headers found in the email.")
    flags: List[str] = Field(default_factory=list, description="List of human-readable warning flags triggered by header analysis.")


class FlaggedUrl(BaseModel):
    url: str = Field(..., description="The suspicious URL.")
    reason: str = Field(..., description="Why this URL was flagged.")


class UrlAnalysisResult(BaseModel):
    total_urls: int = Field(0, description="Total number of unique URLs found in the email.")
    suspicious_urls: int = Field(0, description="Number of URLs that triggered at least one suspicion rule.")
    urls_with_ip_address: int = Field(0, description="URLs that use a raw IP address instead of a domain name.")
    url_shorteners_count: int = Field(0, description="URLs using known URL-shortening services.")
    display_href_mismatches: int = Field(0, description="Anchor tags where the visible link text looks like a URL but differs from the actual href.")
    https_ratio: float = Field(0.0, description="Fraction of URLs using HTTPS (0.0–1.0).", ge=0.0, le=1.0)
    newly_registered_domains: int = Field(0, description="Domains estimated to be less than 30 days old (requires DNS mode).")
    longest_url_length: int = Field(0, description="Character length of the longest URL found.")
    flagged_urls: List[FlaggedUrl] = Field(default_factory=list, description="Detailed list of flagged URLs with reasons.")


class BodyAnalysisResult(BaseModel):
    urgency_score: float = Field(0.0, description="Urgency keyword density (0.0–1.0).", ge=0.0, le=1.0)
    credential_request_detected: bool = Field(False, description="True if the body asks for passwords, SSNs, PINs, or credit card numbers.")
    urgency_keywords_found: List[str] = Field(default_factory=list, description="Urgency phrases found in the body text.")
    action_phrases_found: List[str] = Field(default_factory=list, description="Call-to-action phrases found in the body text.")
    grammar_error_estimate: float = Field(0.0, description="Ratio of words absent from a standard English dictionary (spelling/grammar heuristic).", ge=0.0)
    contains_html_form: bool = Field(False, description="True if the HTML body contains a <form> element.")
    hidden_text_detected: bool = Field(False, description="True if the HTML body uses CSS tricks to hide text (display:none, font-size:0, etc.).")
    body_length: int = Field(0, description="Character count of the plain-text body.")
    flags: List[str] = Field(default_factory=list, description="List of human-readable warning flags triggered by body analysis.")


class StructuralAnalysisResult(BaseModel):
    has_attachments: bool = Field(False, description="True if the email contains one or more attachments.")
    attachment_count: int = Field(0, description="Number of attached MIME parts.")
    dangerous_attachment_types: List[str] = Field(default_factory=list, description="File extensions of dangerous attachments found (.exe, .ps1, .vbs, etc.).")
    has_embedded_images: bool = Field(False, description="True if the email contains inline (CID-referenced) images.")
    multipart_complexity: int = Field(0, description="Maximum depth of the MIME multipart tree.")
    base64_encoded_parts: int = Field(0, description="Number of base64-encoded MIME parts.")
    flags: List[str] = Field(default_factory=list, description="List of human-readable warning flags triggered by structural analysis.")


class AuthAnalysisResult(BaseModel):
    spf_pass: Optional[bool] = Field(None, description="SPF result: true=pass, false=fail, null=header absent.")
    dkim_pass: Optional[bool] = Field(None, description="DKIM result: true=pass, false=fail, null=header absent.")
    dmarc_pass: Optional[bool] = Field(None, description="DMARC result: true=pass, false=fail, null=header absent.")
    auth_summary: str = Field(
        "not_available",
        description="Composite authentication summary: `all_pass`, `partial_fail`, `all_fail`, or `not_available`.",
    )
    flags: List[str] = Field(default_factory=list, description="List of human-readable warning flags triggered by authentication analysis.")


class FeatureBreakdown(BaseModel):
    header_analysis: HeaderAnalysisResult = Field(..., description="Results of the 12 header anomaly features.")
    url_analysis: UrlAnalysisResult = Field(..., description="Results of the 13 URL/link analysis features.")
    body_analysis: BodyAnalysisResult = Field(..., description="Results of the 15 body text analysis features.")
    structural_analysis: StructuralAnalysisResult = Field(..., description="Results of the 8 MIME structural features.")
    auth_analysis: AuthAnalysisResult = Field(..., description="Results of the 4 email authentication features.")
    top_risk_factors: List[RiskFactor] = Field(..., description="Top 5 features ranked by their contribution to the phishing verdict.")


class AnalysisResponse(BaseModel):
    verdict: str = Field(
        ...,
        description='Classification result: `"phishing"` or `"legitimate"`.',
        examples=["phishing"],
    )
    confidence: float = Field(
        ...,
        description="Model confidence for the returned verdict (0.0–1.0). For a phishing verdict this is the phishing class probability; for legitimate it is 1 − phishing probability.",
        ge=0.0,
        le=1.0,
        examples=[0.94],
    )
    risk_level: str = Field(
        ...,
        description='Risk level derived from the phishing probability: `"low"` (< 0.35), `"medium"` (0.35–0.60), `"high"` (0.60–0.85), `"critical"` (> 0.85).',
        examples=["critical"],
    )
    summary: str = Field(
        ...,
        description="One-line human-readable summary of the analysis result.",
        examples=["Email classified as phishing with critical risk (confidence: 94.0%)."],
    )
    feature_breakdown: Optional[FeatureBreakdown] = Field(
        None,
        description="Full per-dimension feature breakdown. Only present when `include_details=true` was set in the request.",
    )
    processing_time_ms: float = Field(
        ...,
        description="End-to-end processing time for this request in milliseconds.",
        examples=[12.4],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "verdict": "phishing",
                    "confidence": 0.94,
                    "risk_level": "critical",
                    "summary": "Email classified as phishing with critical risk (confidence: 94.0%).",
                    "feature_breakdown": None,
                    "processing_time_ms": 12.4,
                }
            ]
        }
    }


class BatchResponse(BaseModel):
    results: List[AnalysisResponse] = Field(..., description="Analysis results in the same order as the input list.")
    total_processed: int = Field(..., description="Number of emails processed.")
    phishing_count: int = Field(..., description="Number of emails classified as phishing.")
    legitimate_count: int = Field(..., description="Number of emails classified as legitimate.")
    processing_time_ms: float = Field(..., description="Total processing time for the entire batch in milliseconds.")
