import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import joblib
import numpy as np

from app.models.parsed_email import ParsedEmail
from app.schemas.response import AnalysisResponse, FeatureBreakdown
from app.services.email_parser import EmailParser
from app.services.explainer import Explainer
from app.services.feature_extractor import FEATURE_ORDER, extract_features, load_feature_config


@dataclass
class ClassificationResult:
    verdict: str
    confidence: float
    risk_level: str
    phishing_probability: float
    feature_importances: Dict[str, float]


class PhishingClassifier:
    def __init__(self, model_path: str, feature_config_path: str, threshold: float = 0.5):
        self.model = joblib.load(model_path)
        self.feature_names: List[str] = (
            load_feature_config(feature_config_path)
            if feature_config_path else FEATURE_ORDER
        )
        self.threshold = threshold
        self._parser = EmailParser()
        self._explainer = Explainer(self.model, self.feature_names)

    def predict(self, features: Dict[str, object]) -> ClassificationResult:
        vector = np.array(
            [float(features.get(name, 0)) for name in self.feature_names],
            dtype=np.float64,
        ).reshape(1, -1)

        proba = self.model.predict_proba(vector)[0]
        phishing_prob = float(proba[1])

        verdict = "phishing" if phishing_prob >= self.threshold else "legitimate"
        confidence = phishing_prob if verdict == "phishing" else 1.0 - phishing_prob
        risk_level = self._compute_risk_level(phishing_prob)

        importances = dict(zip(
            self.feature_names,
            self.model.feature_importances_.tolist(),
        ))

        return ClassificationResult(
            verdict=verdict,
            confidence=round(confidence, 4),
            risk_level=risk_level,
            phishing_probability=round(phishing_prob, 4),
            feature_importances=importances,
        )

    def analyze(self, raw_email: str, include_details: bool = True) -> AnalysisResponse:
        t0 = time.perf_counter()

        parsed = self._parser.parse(raw_email)
        features = extract_features(parsed)
        result = self.predict(features)

        breakdown: Optional[FeatureBreakdown] = None
        if include_details:
            breakdown = self._explainer.build_breakdown(parsed, features, result)

        summary = self._build_summary(result)

        return AnalysisResponse(
            verdict=result.verdict,
            confidence=result.confidence,
            risk_level=result.risk_level,
            summary=summary,
            feature_breakdown=breakdown,
            processing_time_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    @staticmethod
    def _compute_risk_level(phishing_prob: float) -> str:
        if phishing_prob >= 0.85:
            return "critical"
        if phishing_prob >= 0.65:
            return "high"
        if phishing_prob >= 0.40:
            return "medium"
        return "low"

    @staticmethod
    def _build_summary(result: ClassificationResult) -> str:
        pct = round(result.confidence * 100, 1)
        if result.verdict == "phishing":
            return f"This email is likely phishing ({pct}% confidence, {result.risk_level} risk)."
        return f"This email appears legitimate ({pct}% confidence)."
