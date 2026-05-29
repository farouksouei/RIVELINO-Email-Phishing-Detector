"""Load raw email files from data/raw/{phishing,legitimate}/ and build a feature DataFrame."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
from app.services.email_parser import EmailParser
from app.services.feature_extractor import FEATURE_ORDER, extract_features


def load_emails_from_dir(directory: Path, label: int) -> list[dict]:
    parser = EmailParser()
    records = []
    for path in directory.rglob("*"):
        if path.is_file():
            try:
                raw = path.read_text(errors="replace")
                parsed = parser.parse(raw)
                features = extract_features(parsed)
                features["label"] = label
                records.append(features)
            except Exception as e:
                print(f"  Skipping {path.name}: {e}")
    return records


def build_dataset(data_dir: Path = Path("data/raw")) -> pd.DataFrame:
    print("Loading phishing emails...")
    phishing = load_emails_from_dir(data_dir / "phishing", label=1)
    print(f"  Loaded {len(phishing)} phishing emails")

    print("Loading legitimate emails...")
    legitimate = load_emails_from_dir(data_dir / "legitimate", label=0)
    print(f"  Loaded {len(legitimate)} legitimate emails")

    records = phishing + legitimate
    if not records:
        raise ValueError("No emails found. Populate data/raw/phishing/ and data/raw/legitimate/")

    df = pd.DataFrame(records)
    cols = FEATURE_ORDER + ["label"]
    for col in cols:
        if col not in df.columns:
            df[col] = 0
    return df[cols].fillna(0)


if __name__ == "__main__":
    df = build_dataset()
    out = Path("data/processed")
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "features_all.csv", index=False)
    print(f"Saved {len(df)} rows to data/processed/features_all.csv")
