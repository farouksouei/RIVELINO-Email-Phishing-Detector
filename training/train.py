"""Train Random Forest and Gradient Boosting classifiers, serialize the best model."""
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split

from training.evaluate import evaluate_model
from training.preprocess import build_dataset

MODELS_DIR = Path("models")
DATA_DIR = Path("data/processed")


def train():
    processed_csv = DATA_DIR / "features_all.csv"
    if processed_csv.exists():
        print(f"Loading pre-processed features from {processed_csv}")
        df = pd.read_csv(processed_csv)
    else:
        print("No pre-processed features found, building from raw emails...")
        df = build_dataset()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        df.to_csv(processed_csv, index=False)

    X = df.drop(columns=["label"]).values
    y = df["label"].values
    feature_names = [c for c in df.columns if c != "label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=
        y, random_state=42
    )
    print(f"Train: {len(X_train)}, Test: {len(X_test)}")

    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_split=5,
        min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=-1,
    )
    print("Training Random Forest...")
    rf.fit(X_train, y_train)
    rf_metrics = evaluate_model(rf, X_test, y_test, label="Random Forest")

    gb = GradientBoostingClassifier(
        n_estimators=200, learning_rate=0.1, max_depth=5,
        min_samples_split=5, random_state=42,
    )
    print("Training Gradient Boosting...")
    gb.fit(X_train, y_train)
    gb_metrics = evaluate_model(gb, X_test, y_test, label="Gradient Boosting")

    best_model, best_metrics, best_name = (
        (rf, rf_metrics, "RandomForestClassifier")
        if rf_metrics["roc_auc"] >= gb_metrics["roc_auc"]
        else (gb, gb_metrics, "GradientBoostingClassifier")
    )
    print(f"\nBest model: {best_name} (ROC-AUC={best_metrics['roc_auc']:.4f})")

    cv_scores = cross_val_score(best_model, X, y, cv=5, scoring="f1", n_jobs=-1)
    print(f"5-fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "phishing_detector.joblib"
    joblib.dump(best_model, model_path)
    print(f"Model saved to {model_path}")

    importances = dict(zip(feature_names, best_model.feature_importances_))
    top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:20]

    metadata = {
        "model_type": best_name,
        "training_date": str(date.today()),
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "num_features": len(feature_names),
        "feature_names": feature_names,
        "threshold": 0.5,
        "accuracy": best_metrics["accuracy"],
        "precision": best_metrics["precision"],
        "recall": best_metrics["recall"],
        "f1_score": best_metrics["f1"],
        "roc_auc": best_metrics["roc_auc"],
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "top_features": [{"name": n, "importance": round(v, 6)} for n, v in top_features],
        "rf_metrics": rf_metrics,
        "gb_metrics": gb_metrics,
    }
    meta_path = MODELS_DIR / "model_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to {meta_path}")

    return best_model, metadata


if __name__ == "__main__":
    train()
