from fastapi import Request
from fastapi.responses import JSONResponse


class EmailTooLargeError(Exception):
    def __init__(self, size_kb: int, max_kb: int):
        self.size_kb = size_kb
        self.max_kb = max_kb


class InvalidEmailError(Exception):
    def __init__(self, detail: str = "Invalid or empty email input"):
        self.detail = detail


class ModelNotLoadedError(Exception):
    pass


async def email_too_large_handler(request: Request, exc: EmailTooLargeError) -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={"detail": f"Email size {exc.size_kb}KB exceeds maximum allowed {exc.max_kb}KB"},
    )


async def invalid_email_handler(request: Request, exc: InvalidEmailError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"detail": exc.detail},
    )


async def model_not_loaded_handler(request: Request, exc: ModelNotLoadedError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "ML model is not loaded. Check server startup logs."},
    )
