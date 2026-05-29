import time
from fastapi import APIRouter, Request
from app.schemas.request import BatchRequest
from app.schemas.response import BatchResponse
from app.core.exceptions import ModelNotLoadedError

router = APIRouter()


@router.post("/batch", response_model=BatchResponse)
async def batch_analyze(body: BatchRequest, request: Request):
    if not hasattr(request.app.state, "model") or request.app.state.model is None:
        raise ModelNotLoadedError()

    t0 = time.perf_counter()
    results = []
    for email_req in body.emails:
        r = request.app.state.model.analyze(
            raw_email=email_req.raw_email,
            include_details=email_req.include_details,
        )
        results.append(r)

    phishing_count = sum(1 for r in results if r.verdict == "phishing")
    return BatchResponse(
        results=results,
        total_processed=len(results),
        phishing_count=phishing_count,
        legitimate_count=len(results) - phishing_count,
        processing_time_ms=round((time.perf_counter() - t0) * 1000, 2),
    )
