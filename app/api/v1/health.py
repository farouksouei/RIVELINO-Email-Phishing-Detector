import time
from fastapi import APIRouter, Request

router = APIRouter()

_start_time = time.time()


@router.get("/health")
async def health_check(request: Request):
    model_loaded = hasattr(request.app.state, "model") and request.app.state.model is not None
    return {
        "status": "healthy",
        "model_loaded": model_loaded,
        "version": request.app.state.settings.APP_VERSION,
        "uptime_seconds": round(time.time() - _start_time, 1),
    }
