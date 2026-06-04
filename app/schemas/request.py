from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class EmailTextRequest(BaseModel):
    raw_email: str = Field(
        ...,
        description=(
            "Full raw email in RFC 5322 format — headers **and** body. "
            "Including server-inserted headers (Received, Authentication-Results) "
            "enables SPF/DKIM/DMARC feature extraction."
        ),
        examples=[
            "From: support@paypa1-secure.tk\r\n"
            "Reply-To: collect@evil.ru\r\n"
            "Subject: URGENT: Your account has been suspended!\r\n"
            "To: victim@example.com\r\n"
            "\r\n"
            "Dear Customer,\r\n\r\n"
            "Your account will be PERMANENTLY SUSPENDED unless you verify immediately.\r\n"
            "Click here now: http://192.168.1.1/login?verify=account\r\n"
        ],
    )
    include_details: bool = Field(
        True,
        description=(
            "When `true` the response includes the full `feature_breakdown` object "
            "and the `top_risk_factors` list. Set to `false` for a lightweight "
            "verdict-only response."
        ),
    )

    @field_validator("raw_email")
    @classmethod
    def must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("raw_email must not be empty")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "raw_email": (
                        "From: support@paypa1-secure.tk\r\n"
                        "Reply-To: collect@evil.ru\r\n"
                        "Subject: URGENT: Your account has been suspended!\r\n"
                        "To: victim@example.com\r\n"
                        "\r\n"
                        "Dear Customer,\r\n\r\n"
                        "Your account will be PERMANENTLY SUSPENDED unless you "
                        "verify immediately.\r\n"
                        "Click here: http://192.168.1.1/login?verify=account\r\n"
                    ),
                    "include_details": True,
                }
            ]
        }
    }


class EmailHeadersRequest(BaseModel):
    sender: str = Field(..., description="Sender email address (From header).")
    reply_to: Optional[str] = Field(None, description="Reply-To address, if present.")
    subject: str = Field(..., description="Email subject line.")
    body_text: str = Field(..., description="Plain-text email body.")
    body_html: Optional[str] = Field(None, description="HTML email body, if available.")
    received_headers: Optional[List[str]] = Field(
        None, description="List of Received headers in order (oldest first)."
    )
    urls: Optional[List[str]] = Field(
        None, description="Pre-extracted list of URLs found in the email."
    )
    attachments: Optional[List[str]] = Field(
        None, description="List of attachment filenames (content not required)."
    )


class BatchRequest(BaseModel):
    emails: List[EmailTextRequest] = Field(
        ...,
        description="List of emails to analyse. Maximum **50** per request.",
        min_length=1,
        max_length=50,
    )

    @field_validator("emails")
    @classmethod
    def max_fifty(cls, v: list) -> list:
        if len(v) > 50:
            raise ValueError("Batch size must not exceed 50 emails")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "emails": [
                        {
                            "raw_email": "From: hr@company.com\nSubject: Meeting tomorrow\n\nHi team,",
                            "include_details": False,
                        },
                        {
                            "raw_email": (
                                "From: noreply@bank-secure.tk\n"
                                "Subject: VERIFY NOW or account closed!!!\n\n"
                                "Dear Customer, click immediately: http://1.2.3.4/verify"
                            ),
                            "include_details": True,
                        },
                    ]
                }
            ]
        }
    }