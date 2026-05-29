from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    APP_NAME: str = "Phishing Email Detector"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    MODEL_PATH: Path = Path("models/phishing_detector.joblib")
    MODEL_METADATA_PATH: Path = Path("models/model_metadata.json")
    FEATURE_CONFIG_PATH: Path = Path("training/feature_config.json")

    CONFIDENCE_THRESHOLD: float = 0.5
    MAX_EMAIL_SIZE_KB: int = 5120

    ALLOWED_ORIGINS: List[str] = ["*"]


settings = Settings()
