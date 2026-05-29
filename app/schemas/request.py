from typing import List, Optional
from pydantic import BaseModel, field_validator


class EmailTextRequest(BaseModel):
    raw_email: str
    include_details: bool = True

    @field_validator("raw_email")
    @classmethod
    def must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("raw_email must not be empty")
        return v


class EmailHeadersRequest(BaseModel):
    sender: str
    reply_to: Optional[str] = None
    subject: str
    body_text: str
    body_html: Optional[str] = None
    received_headers: Optional[List[str]] = None
    urls: Optional[List[str]] = None
    attachments: Optional[List[str]] = None


class BatchRequest(BaseModel):
    emails: List[EmailTextRequest]

    @field_validator("emails")
    @classmethod
    def max_fifty(cls, v: list) -> list:
        if len(v) > 50:
            raise ValueError("Batch size must not exceed 50 emails")
        return v
