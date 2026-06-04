import time

from fastapi import APIRouter, Request

router = APIRouter()

_start_time = time.time()


@router.get(
    "/health",
    summary="Liveness check",
    response_description="Server status, model-loaded flag, version, and uptime.",
    responses={
        200: {
            "description": "Server is healthy.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "healthy",
                        "model_loaded": True,
                        "version": "1.0.0",
                        "uptime_seconds": 3600.0,
                    }
                }
            },
        }
    },
    tags=["health"],
)
async def health_check(request: Request):
    """
    Returns the current health status of the API.

    - **status** — always `"healthy"` when the server is reachable.
    - **model_loaded** — `true` if the ML model was loaded successfully at startup.
      If `false`, the `/analyze` and `/batch` endpoints will return **503**.
    - **version** — API semantic version string.
    - **uptime_seconds** — seconds elapsed since the server process started.
    """
    model_loaded = hasattr(request.app.state, "model") and request.app.state.model is not None
    return {
        "status": "healthy",
        "model_loaded": model_loaded,
        "version": request.app.state.settings.APP_VERSION,
        "uptime_seconds": round(time.time() - _start_time, 1),
    }