import time
from fastapi import APIRouter, Request, UploadFile, File, HTTPException
from app.schemas.request import EmailTextRequest
from app.schemas.response import AnalysisResponse
from app.core.exceptions import ModelNotLoadedError, InvalidEmailError, EmailTooLargeError

router = APIRouter()


def _require_model(request: Request):
    if not hasattr(request.app.state, "model") or request.app.state.model is None:
        raise ModelNotLoadedError()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(body: EmailTextRequest, request: Request):
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


@router.post("/analyze/upload", response_model=AnalysisResponse)
async def analyze_upload(request: Request, email_file: UploadFile = File(...)):
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
