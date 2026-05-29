from typing import Any, List, Optional
from pydantic import BaseModel


class RiskFactor(BaseModel):
    feature_name: str
    description: str
    value: Any
    risk_contribution: float


class HeaderAnalysisResult(BaseModel):
    sender_display_name: Optional[str] = None
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    from_replyto_mismatch: bool = False
    display_name_email_mismatch: bool = False
    suspicious_received_chain: bool = False
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    num_received_headers: int = 0
    flags: List[str] = []


class FlaggedUrl(BaseModel):
    url: str
    reason: str


class UrlAnalysisResult(BaseModel):
    total_urls: int = 0
    suspicious_urls: int = 0
    urls_with_ip_address: int = 0
    url_shorteners_count: int = 0
    display_href_mismatches: int = 0
    https_ratio: float = 0.0
    newly_registered_domains: int = 0
    longest_url_length: int = 0
    flagged_urls: List[FlaggedUrl] = []


class BodyAnalysisResult(BaseModel):
    urgency_score: float = 0.0
    credential_request_detected: bool = False
    urgency_keywords_found: List[str] = []
    action_phrases_found: List[str] = []
    grammar_error_estimate: float = 0.0
    contains_html_form: bool = False
    hidden_text_detected: bool = False
    body_length: int = 0
    flags: List[str] = []


class StructuralAnalysisResult(BaseModel):
    has_attachments: bool = False
    attachment_count: int = 0
    dangerous_attachment_types: List[str] = []
    has_embedded_images: bool = False
    multipart_complexity: int = 0
    base64_encoded_parts: int = 0
    flags: List[str] = []


class AuthAnalysisResult(BaseModel):
    spf_pass: Optional[bool] = None
    dkim_pass: Optional[bool] = None
    dmarc_pass: Optional[bool] = None
    auth_summary: str = "not_available"
    flags: List[str] = []


class FeatureBreakdown(BaseModel):
    header_analysis: HeaderAnalysisResult
    url_analysis: UrlAnalysisResult
    body_analysis: BodyAnalysisResult
    structural_analysis: StructuralAnalysisResult
    auth_analysis: AuthAnalysisResult
    top_risk_factors: List[RiskFactor]


class AnalysisResponse(BaseModel):
    verdict: str
    confidence: float
    risk_level: str
    summary: str
    feature_breakdown: Optional[FeatureBreakdown] = None
    processing_time_ms: float


class BatchResponse(BaseModel):
    results: List[AnalysisResponse]
    total_processed: int
    phishing_count: int
    legitimate_count: int
    processing_time_ms: float
