# RIVELINO — AI-Powered Email Phishing Detector

> **Cybersecurity project** — MSc in Engineering in Computer Science · University of Messina  
> **Course:** Cybersecurity · **Professor:** Prof. Francesco Longo · **Student:** Mohamed Farouk Souiai

RIVELINO classifies emails as **phishing** or **legitimate** using a trained **Gradient Boosting** classifier backed by **52 hand-crafted security features** extracted across five analytical dimensions. It is exposed as a **FastAPI REST API** with a browser demo UI and is fully containerised with Docker.

---

## Model Performance

| Metric | Gradient Boosting (deployed) | Random Forest |
|---|---|---|
| Accuracy | **98.90 %** | 98.51 % |
| Precision | **98.71 %** | 97.45 % |
| Recall | **97.05 %** | 96.84 % |
| F1-Score | **97.87 %** | 97.14 % |
| ROC-AUC | **99.86 %** | 99.86 % |

Evaluated on a held-out test set of **1,815 emails** (SpamAssassin + Nazario phishing corpus, 9,072 total).

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start — Docker](#quick-start--docker)
- [Quick Start — Local](#quick-start--local)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Training the Model](#training-the-model)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)

---

## Features

### 52 detection features across 5 dimensions

| Dimension | Count | Examples |
|---|---|---|
| Header anomalies | 12 | Display-name spoofing, Reply-To hijack, freemail senders, fake Re:/Fwd: threads |
| URL / link analysis | 13 | IP-based URLs, href mismatches, URL shorteners, suspicious TLDs (.tk/.ml/.ga) |
| Body text | 15 | Urgency keywords, credential requests, hidden CSS text, generic greetings |
| MIME structure | 8 | Dangerous attachments (.exe/.ps1/.vbs), double extensions, base64 depth |
| Email authentication | 4 | SPF / DKIM / DMARC pass/fail/absent + composite score |

### What you get per analysis

- **Verdict** — `phishing` or `legitimate`
- **Confidence score** — 0.0–1.0 (model probability)
- **Risk level** — `low` / `medium` / `high` / `critical`
- **Top 5 risk factors** — ranked features that drove the decision, with human-readable descriptions
- **Full feature breakdown** — per-dimension results across all 52 features

---

## Architecture

```
Client (browser / curl / Postman)
        │
        ▼
┌─────────────────────────────────────────┐
│            FastAPI  (port 8000)          │
│  /analyze  /analyze/upload  /batch      │
│  /health   /model/info                  │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│           Processing Pipeline            │
│                                         │
│  Email Parser                           │
│    → Feature Extractor (52 features)    │
│    → GradientBoosting classifier        │
│    → Explainer (top risk factors)       │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│           Model Layer                   │
│  phishing_detector.joblib               │
│  model_metadata.json                    │
│  training/feature_config.json           │
└─────────────────────────────────────────┘
```

**Stack:** FastAPI · Uvicorn · scikit-learn 1.8.0 · numpy 2.4.6 · joblib 1.5.3 · tldextract · dnspython · Docker

---

## Quick Start — Docker

**Recommended.** No Python environment setup required.

```bash
# 1. Clone the repository
git clone <repo-url>
cd RIVELINO-Email-Phishing-Detector

# 2. Build and start
docker-compose -f docker/docker-compose.yml up --build

# 3. Open the browser demo
open http://localhost:8000/static/index.html

# 4. Browse the interactive API docs
open http://localhost:8000/docs
```

> The trained model is bundled in `models/` and mounted as a volume — no training step needed to run the API.

---

## Quick Start — Local

```bash
# 1. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy and edit environment variables (optional)
cp .env.example .env

# 4. Start the server
uvicorn app.main:app --reload --port 8000
```

Visit:
- **`http://localhost:8000/docs`** — Swagger UI (interactive)
- **`http://localhost:8000/redoc`** — ReDoc (read-only)
- **`http://localhost:8000/static/index.html`** — browser demo

---

## API Reference

### `POST /api/v1/analyze` — Analyse a single email

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_email": "From: security@paypa1-secure.tk\r\nSubject: URGENT verify now\r\n\r\nDear Customer, click immediately: http://1.2.3.4/login",
    "include_details": true
  }'
```

<details>
<summary>Example response</summary>

```json
{
  "verdict": "phishing",
  "confidence": 0.94,
  "risk_level": "critical",
  "summary": "Email classified as phishing with critical risk (confidence: 94.0%).",
  "feature_breakdown": {
    "header_analysis": {
      "sender_domain": "paypa1-secure.tk",
      "from_replyto_mismatch": true,
      "flags": ["sender_is_freemail_equivalent", "suspicious_tld"]
    },
    "url_analysis": {
      "total_urls": 1,
      "urls_with_ip_address": 1,
      "flagged_urls": [
        { "url": "http://1.2.3.4/login", "reason": "Raw IP address used instead of domain" }
      ]
    },
    "top_risk_factors": [
      {
        "feature_name": "spelling_error_estimate",
        "description": "High ratio of non-standard words in the email body",
        "value": 0.38,
        "risk_contribution": 0.29
      }
    ]
  },
  "processing_time_ms": 11.3
}
```
</details>

---

### `POST /api/v1/analyze/upload` — Upload a `.eml` file

```bash
curl -X POST http://localhost:8000/api/v1/analyze/upload \
  -F "email_file=@data/sample_emails/phishing_example_1.eml"
```

---

### `POST /api/v1/batch` — Analyse up to 50 emails

```bash
curl -X POST http://localhost:8000/api/v1/batch \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      { "raw_email": "From: hr@company.com\nSubject: Meeting\n\nHi team,", "include_details": false },
      { "raw_email": "From: noreply@bank-secure.tk\nSubject: VERIFY NOW!!!\n\nClick: http://1.2.3.4", "include_details": false }
    ]
  }'
```

---

### `GET /api/v1/health` — Liveness check

```bash
curl http://localhost:8000/api/v1/health
# {"status":"healthy","model_loaded":true,"version":"1.0.0","uptime_seconds":42.1}
```

---

### `GET /api/v1/model/info` — Classifier metadata

```bash
curl http://localhost:8000/api/v1/model/info
```

Returns training date, dataset size, all 52 feature names, evaluation metrics, and top-20 feature importances.

---

### Risk levels

| Level | Phishing probability | Meaning |
|---|---|---|
| `low` | < 0.35 | Almost certainly legitimate |
| `medium` | 0.35 – 0.60 | Borderline — manual review recommended |
| `high` | 0.60 – 0.85 | Likely phishing |
| `critical` | > 0.85 | Almost certainly phishing |

---

## Configuration

Copy `.env.example` to `.env` and override as needed:

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `Phishing Email Detector` | Application name shown in API docs |
| `APP_VERSION` | `1.0.0` | Semantic version |
| `DEBUG` | `false` | Enable FastAPI debug mode |
| `MODEL_PATH` | `models/phishing_detector.joblib` | Path to serialised model |
| `MODEL_METADATA_PATH` | `models/model_metadata.json` | Path to model metadata |
| `FEATURE_CONFIG_PATH` | `training/feature_config.json` | Path to feature definitions |
| `CONFIDENCE_THRESHOLD` | `0.5` | Decision threshold (phishing if prob ≥ threshold) |
| `MAX_EMAIL_SIZE_KB` | `5120` | Maximum accepted email size (5 MB) |
| `ALLOWED_ORIGINS` | `["*"]` | CORS allowed origins |

---

## Training the Model

The trained model is already included in `models/`. Run training only if you want to retrain on a different dataset or reproduce the results.

```bash
# 1. Place raw emails in the correct directories:
#    data/raw/phishing/     ← phishing emails (one file per email)
#    data/raw/legitimate/   ← legitimate emails

# 2. Run the training pipeline
python training/train.py

# 3. Evaluate both models
python training/evaluate.py
```

The script trains both **Random Forest** and **Gradient Boosting**, prints a full comparison, serialises the best model to `models/phishing_detector.joblib`, and writes metrics to `models/model_metadata.json`.

### Datasets used

| Dataset | Type | Size |
|---|---|---|
| SpamAssassin Public Corpus | Mixed (phishing + legitimate) | ~6,000 emails |
| Nazario Phishing Corpus | Phishing | ~7,000 emails |

> **Note:** Training must be performed with **scikit-learn 1.8.0** (pinned in `requirements.txt`). Loading a model trained with a different version will raise `ModuleNotFoundError` at startup.

---

## Running Tests

```bash
pip install -r requirements.txt

# Run all tests
pytest tests/ -v

# Run a specific module
pytest tests/test_header_features.py -v
pytest tests/test_api_analyze.py -v
```

### Test coverage by module

| File | What it tests |
|---|---|
| `test_email_parser.py` | Raw email → ParsedEmail, edge cases, encoding |
| `test_header_features.py` | All 12 header anomaly features |
| `test_url_features.py` | All 13 URL analysis features |
| `test_body_features.py` | All 15 body text features |
| `test_structural_features.py` | All 8 MIME structural features |
| `test_auth_features.py` | All 4 authentication features |
| `test_api_analyze.py` | Full API integration: POST → verdict |

---

## Project Structure

```
RIVELINO-Email-Phishing-Detector/
│
├── app/
│   ├── main.py                     # FastAPI app, lifespan, CORS, OpenAPI metadata
│   ├── api/
│   │   ├── router.py               # Main API router
│   │   └── v1/
│   │       ├── analyze.py          # POST /analyze, /analyze/upload
│   │       ├── batch.py            # POST /batch
│   │       ├── health.py           # GET /health
│   │       └── model_info.py       # GET /model/info
│   ├── core/
│   │   ├── config.py               # Pydantic Settings (env vars)
│   │   └── exceptions.py           # Custom exceptions + handlers
│   ├── schemas/
│   │   ├── request.py              # EmailTextRequest, BatchRequest
│   │   └── response.py             # AnalysisResponse, FeatureBreakdown, …
│   ├── services/
│   │   ├── email_parser.py         # Raw email → ParsedEmail
│   │   ├── feature_extractor.py    # ParsedEmail → 52-feature dict
│   │   ├── classifier.py           # Load model, predict, risk level
│   │   └── explainer.py            # Feature importances → risk factors
│   ├── features/
│   │   ├── header_features.py      # 12 header anomaly features
│   │   ├── url_features.py         # 13 URL/link features
│   │   ├── body_features.py        # 15 body text features
│   │   ├── structural_features.py  # 8 MIME structural features
│   │   └── auth_features.py        # 4 authentication features
│   ├── models/
│   │   └── parsed_email.py         # ParsedEmail dataclass
│   └── static/                     # Browser demo (HTML/CSS/JS)
│
├── training/
│   ├── train.py                    # Training pipeline (RF + GB)
│   ├── evaluate.py                 # Metrics, confusion matrix, ROC-AUC
│   ├── preprocess.py               # Dataset loading and label mapping
│   └── feature_config.json         # Canonical feature name list and groups
│
├── models/
│   ├── phishing_detector.joblib    # Trained GradientBoosting model
│   └── model_metadata.json         # Metrics, feature importances, versions
│
├── data/
│   ├── raw/                        # Raw email corpora (gitignored)
│   │   ├── phishing/
│   │   └── legitimate/
│   ├── processed/                  # Feature CSVs produced by training
│   └── sample_emails/              # .eml files for testing and demo
│
├── tests/                          # pytest unit + integration tests
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

---

## Acknowledgements

- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
- [Nazario Phishing Corpus](http://monkey.org/~jose/phishing/)
- [FastAPI](https://fastapi.tiangolo.com/) · [scikit-learn](https://scikit-learn.org/) · [tldextract](https://github.com/john-kurkowski/tldextract)