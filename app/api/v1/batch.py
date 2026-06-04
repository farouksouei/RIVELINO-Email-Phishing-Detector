import time

from fastapi import APIRouter, Request

from app.core.exceptions import ModelNotLoadedError
from app.schemas.request import BatchRequest
from app.schemas.response import BatchResponse

router = APIRouter()


@router.post(
    "/batch",
    response_model=BatchResponse,
    summary="Analyse multiple emails in one request",
    response_description="Per-email verdicts plus aggregate counts for the whole batch.",
    responses={
        200: {
            "description": "All emails processed successfully.",
            "content": {
                "application/json": {
                    "example": {
                        "results": [
                            {
                                "verdict": "legitimate",
                                "confidence": 0.98,
                                "risk_level": "low",
                                "summary": "Email classified as legitimate with low risk (confidence: 98.0%).",
                                "feature_breakdown": None,
                                "processing_time_ms": 8.1,
                            },
                            {
                                "verdict": "phishing",
                                "confidence": 0.91,
                                "risk_level": "critical",
                                "summary": "Email classified as phishing with critical risk (confidence: 91.0%).",
                                "feature_breakdown": None,
                                "processing_time_ms": 10.3,
                            },
                        ],
                        "total_processed": 2,
                        "phishing_count": 1,
                        "legitimate_count": 1,
                        "processing_time_ms": 18.4,
                    }
                }
            },
        },
        422: {"description": "Batch exceeds 50 emails or input validation failed."},
        503: {"description": "ML model is not loaded."},
    },
    tags=["batch"],
)
async def batch_analyze(body: BatchRequest, request: Request):
    """
    Classify up to **50 emails** in a single HTTP request.

    Results are returned in the **same order** as the input list.
    The response also includes aggregate counts (`phishing_count`, `legitimate_count`)
    and the total processing time for the whole batch.

    Tip: set `include_details=false` on individual emails when you only need the
    verdict, to reduce response size for large batches.
    """
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