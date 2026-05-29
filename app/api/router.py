from fastapi import APIRouter
from app.api.v1 import health, analyze, batch, model_info

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router, tags=["health"])
api_router.include_router(analyze.router, tags=["analysis"])
api_router.include_router(batch.router, tags=["analysis"])
api_router.include_router(model_info.router, tags=["model"])
