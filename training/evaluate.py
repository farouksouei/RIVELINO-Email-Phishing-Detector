"""Evaluation utilities for trained classifiers."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate_model(model, X_test, y_test, label: str = "Model") -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n--- {label} ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1:        {f1:.4f}")
    print(f"ROC-AUC:   {roc:.4f}")
    print(f"Confusion matrix:\n{np.array(cm)}")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    return {
        "accuracy": round(float(acc), 6),
        "precision": round(float(prec), 6),
        "recall": round(float(rec), 6),
        "f1": round(float(f1), 6),
        "roc_auc": round(float(roc), 6),
        "confusion_matrix": cm,
    }


if __name__ == "__main__":
    import joblib
    import pandas as pd
    from sklearn.model_selection import train_test_split

    df = pd.read_csv("data/processed/features_all.csv")
    X = df.drop(columns=["label"]).values
    y = df["label"].values
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    model = joblib.load("models/phishing_detector.joblib")
    evaluate_model(model, X_test, y_test, label="Loaded Model")
