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


_DESCRIPTION = """
## RIVELINO — AI-Powered Email Phishing Detector

RIVELINO analyses raw email messages and classifies them as **phishing** or **legitimate**
using a trained **Gradient Boosting** classifier backed by **52 hand-crafted security features**
grouped across five analytical dimensions.

### Feature dimensions
| Group | Features | Examples |
|---|---|---|
| Header anomalies | 12 | Display-name spoofing, Reply-To hijack, freemail senders |
| URL / link analysis | 13 | IP-based URLs, href mismatches, shorteners, suspicious TLDs |
| Body text | 15 | Urgency keywords, credential requests, hidden text |
| MIME structure | 8 | Dangerous attachments, double extensions, MIME depth |
| Email authentication | 4 | SPF, DKIM, DMARC pass/fail/absent |

### Model performance (test set — 1,815 emails)
- **Accuracy** 98.90 % · **Precision** 98.71 % · **Recall** 97.05 %
- **F1** 97.87 % · **ROC-AUC** 99.86 %

### Quick start
```bash
curl -X POST http://localhost:8000/api/v1/analyze \\
  -H "Content-Type: application/json" \\
  -d '{"raw_email": "From: attacker@evil.tk\\nSubject: URGENT verify now\\n\\nClick here immediately!"}'
```
"""

_TAGS_METADATA = [
    {
        "name": "analysis",
        "description": (
            "Core detection endpoints. Submit a single email as **raw RFC 5322 text**, "
            "as a **JSON payload**, or as an uploaded **.eml file**. "
            "Every response includes a verdict, confidence score, risk level, and — "
            "when `include_details=true` — a full per-dimension feature breakdown and "
            "a ranked list of the top risk factors."
        ),
    },
    {
        "name": "batch",
        "description": (
            "Submit up to **50 emails** in a single request. "
            "Responses are returned in the same order as the input list."
        ),
    },
    {
        "name": "model",
        "description": (
            "Inspect the loaded classifier: training date, dataset size, "
            "all 52 feature names, and the full evaluation metrics."
        ),
    },
    {
        "name": "health",
        "description": "Liveness check. Returns model-loaded flag, API version, and server uptime.",
    },
]


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=_DESCRIPTION,
        openapi_tags=_TAGS_METADATA,
        contact={
            "name": "Mohamed Farouk Souiai",
            "email": "farouksouei@gmail.com",
        },
        license_info={
            "name": "MIT",
        },
        docs_url="/docs",
        redoc_url="/redoc",
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
