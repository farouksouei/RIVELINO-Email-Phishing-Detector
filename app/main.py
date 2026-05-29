from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import (
    EmailTooLargeError,
    InvalidEmailError,
    ModelNotLoadedError,
    email_too_large_handler,
    invalid_email_handler,
    model_not_loaded_handler,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.settings = settings

    model_path: Path = settings.MODEL_PATH
    if model_path.exists():
        from app.services.classifier import PhishingClassifier
        app.state.model = PhishingClassifier(
            model_path=str(model_path),
            feature_config_path=str(settings.FEATURE_CONFIG_PATH),
            threshold=settings.CONFIDENCE_THRESHOLD,
        )
    else:
        app.state.model = None

    yield

    app.state.model = None


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="AI-powered phishing email detection API",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_exception_handler(EmailTooLargeError, email_too_large_handler)
    app.add_exception_handler(InvalidEmailError, invalid_email_handler)
    app.add_exception_handler(ModelNotLoadedError, model_not_loaded_handler)

    app.include_router(api_router)

    static_dir = Path("app/static")
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


app = create_app()
