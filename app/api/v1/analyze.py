import time

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from app.core.exceptions import EmailTooLargeError, InvalidEmailError, ModelNotLoadedError
from app.schemas.request import EmailTextRequest
from app.schemas.response import AnalysisResponse

router = APIRouter()

_PHISHING_EXAMPLE = {
    "verdict": "phishing",
    "confidence": 0.94,
    "risk_level": "critical",
    "summary": "Email classified as phishing with critical risk (confidence: 94.0%).",
    "feature_breakdown": None,
    "processing_time_ms": 11.3,
}

_LEGIT_EXAMPLE = {
    "verdict": "legitimate",
    "confidence": 0.98,
    "risk_level": "low",
    "summary": "Email classified as legitimate with low risk (confidence: 98.0%).",
    "feature_breakdown": None,
    "processing_time_ms": 9.7,
}


def _require_model(request: Request):
    if not hasattr(request.app.state, "model") or request.app.state.model is None:
        raise ModelNotLoadedError()


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyse a single email",
    response_description="Phishing verdict with confidence score, risk level, and optional feature breakdown.",
    responses={
        200: {
            "description": "Analysis completed successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "phishing": {
                            "summary": "Phishing email detected",
                            "value": _PHISHING_EXAMPLE,
                        },
                        "legitimate": {
                            "summary": "Legitimate email",
                            "value": _LEGIT_EXAMPLE,
                        },
                    }
                }
            },
        },
        400: {"description": "Empty or unparseable email input."},
        413: {"description": "Email payload exceeds the configured size limit."},
        503: {"description": "ML model is not loaded. Start the server with a valid model file."},
    },
    tags=["analysis"],
)
async def analyze_email(body: EmailTextRequest, request: Request):
    """
    Classify a single email as **phishing** or **legitimate**.

    Submit the full raw email (RFC 5322 format — headers + body) as the `raw_email` field.
    Including server-inserted headers such as `Received` and `Authentication-Results`
    enables SPF / DKIM / DMARC feature extraction and improves accuracy.

    Set `include_details=true` (default) to receive the full `feature_breakdown` object
    and the `top_risk_factors` list. Set it to `false` for a lightweight verdict-only response.
    """
    _require_model(request)
    settings = request.app.state.settings

    size_kb = len(body.raw_email.encode()) // 1024
    if size_kb > settings.MAX_EMAIL_SIZE_KB:
        raise EmailTooLargeError(size_kb, settings.MAX_EMAIL_SIZE_KB)

    t0 = time.perf_counter()
    result = request.app.state.model.analyze(
        raw_email=body.raw_email,
        include_details=body.include_details,
    )
    result.processing_time_ms = round((time.perf_counter() - t0) * 1000, 2)
    return result


@router.post(
    "/analyze/upload",
    response_model=AnalysisResponse,
    summary="Analyse an uploaded .eml file",
    response_description="Phishing verdict with confidence score, risk level, and feature breakdown.",
    responses={
        200: {
            "description": "Analysis completed successfully.",
            "content": {
                "application/json": {
                    "example": _PHISHING_EXAMPLE,
                }
            },
        },
        400: {"description": "Unsupported file type or file could not be decoded as UTF-8."},
        413: {"description": "Uploaded file exceeds the configured size limit."},
        503: {"description": "ML model is not loaded."},
    },
    tags=["analysis"],
)
async def analyze_upload(request: Request, email_file: UploadFile = File(..., description="Raw email file in .eml or .msg format.")):
    """
    Classify an email uploaded as a **.eml** or **.msg** file.

    The file is read, decoded as UTF-8, and passed through the same pipeline as
    the `/analyze` endpoint. The `include_details` flag defaults to `true`.

    Use this endpoint when testing with saved email files rather than pasted text.
    """
    _require_model(request)
    settings = request.app.state.settings

    filename = email_file.filename or ""
    if not filename.lower().endswith((".eml", ".msg")):
        raise InvalidEmailError("Only .eml and .msg files are accepted")

    content = await email_file.read()
    size_kb = len(content) // 1024
    if size_kb > settings.MAX_EMAIL_SIZE_KB:
        raise EmailTooLargeError(size_kb, settings.MAX_EMAIL_SIZE_KB)

    try:
        raw_email = content.decode("utf-8", errors="replace")
    except Exception:
        raise InvalidEmailError("Could not decode uploaded file")

    t0 = time.perf_counter()
    result = request.app.state.model.analyze(raw_email=raw_email, include_details=True)
    result.processing_time_ms = round((time.perf_counter() - t0) * 1000, 2)
    return result