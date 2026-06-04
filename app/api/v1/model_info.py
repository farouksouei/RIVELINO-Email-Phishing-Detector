import json

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.get(
    "/model/info",
    summary="Classifier metadata",
    response_description="Training metadata, evaluation metrics, and the full feature list.",
    responses={
        200: {
            "description": "Model metadata retrieved successfully.",
            "content": {
                "application/json": {
                    "example": {
                        "model_type": "GradientBoostingClassifier",
                        "sklearn_version": "1.8.0",
                        "training_date": "2026-05-29",
                        "dataset_size": 9072,
                        "train_size": 7257,
                        "test_size": 1815,
                        "num_features": 52,
                        "threshold": 0.5,
                        "accuracy": 0.98898,
                        "precision": 0.987124,
                        "recall": 0.970464,
                        "f1_score": 0.978723,
                        "roc_auc": 0.998614,
                        "cv_f1_mean": 0.960183,
                        "cv_f1_std": 0.017987,
                        "feature_names": [
                            "from_display_domain_mismatch",
                            "from_replyto_domain_mismatch",
                            "...",
                            "auth_score",
                        ],
                        "top_features": [
                            {"name": "spelling_error_estimate", "importance": 0.290426},
                            {"name": "excessive_exclamation_marks", "importance": 0.152735},
                        ],
                    }
                }
            },
        },
        404: {"description": "Model metadata file not found. Run the training pipeline first."},
    },
    tags=["model"],
)
async def model_info(request: Request):
    """
    Returns the metadata recorded when the model was last trained.

    Includes:
    - **model_type** and **sklearn_version** used for training
    - **training_date** and dataset split sizes
    - Full evaluation metrics: accuracy, precision, recall, F1, ROC-AUC
    - 5-fold cross-validation F1 mean and standard deviation
    - Ordered list of all **52 feature names**
    - Top-20 features ranked by Gradient Boosting feature importance
    - Per-model comparison metrics for both Random Forest and Gradient Boosting
    """
    metadata_path = request.app.state.settings.MODEL_METADATA_PATH
    if not metadata_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Model metadata not found. Train the model first.",
        )
    with open(metadata_path) as f:
        return json.load(f)