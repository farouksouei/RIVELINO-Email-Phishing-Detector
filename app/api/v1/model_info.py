import json
from fastapi import APIRouter, Request, HTTPException

router = APIRouter()


@router.get("/model/info")
async def model_info(request: Request):
    metadata_path = request.app.state.settings.MODEL_METADATA_PATH
    if not metadata_path.exists():
        raise HTTPException(status_code=404, detail="Model metadata not found. Train the model first.")
    with open(metadata_path) as f:
        return json.load(f)
