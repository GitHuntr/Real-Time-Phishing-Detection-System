# PhishGuard — Real-Time Phishing Detection System

AI-powered phishing URL detection using XGBoost, SHAP explainability, and a cyber-themed web dashboard.

---

## Project Structure

```
phishguard/
├── backend/
│   ├── main.py               # FastAPI application
│   ├── feature_extractor.py  # 28+ lexical + domain features
│   ├── model_trainer.py      # LR / Random Forest / XGBoost comparison
│   ├── predictor.py          # Prediction orchestrator
│   ├── explainer.py          # SHAP explainability engine
│   ├── models/               # Saved .pkl model artifacts
│   └── requirements.txt
├── frontend/
│   ├── index.html            # Cyber-themed dashboard
│   ├── css/style.css
│   └── js/app.js
├── chrome_extension/
│   ├── manifest.json         # Manifest V3
│   ├── popup.html / popup.js # Extension popup UI
│   ├── background.js         # Service worker
│   └── content.js            # Page warning injector
└── data/                     # Place your dataset CSV here
```

---

## Quick Start

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Train the model

Download a phishing dataset (e.g., from [Kaggle Phishing URL Dataset](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls)) and place it in `data/`.

```bash
cd backend
python model_trainer.py --data ../data/phishing_dataset.csv --output phishguard_model.pkl
```

The trainer will:
- Compare Logistic Regression, Random Forest, and XGBoost
- Apply SMOTE for class imbalance
- Save the best model (highest F1 score) to `backend/models/`
- Print a full comparison table and classification report

### 3. Start the API server

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API is now live at `http://localhost:8000`
- Interactive docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### 4. Open the dashboard

Open `frontend/index.html` in your browser, or serve it:

```bash
cd frontend
python3 -m http.server 3000
# Open http://localhost:3000
```

---

## API Reference

### POST /predict

```json
{
  "url": "http://suspicious-site.xyz/login",
  "include_domain_features": false
}
```

**Response:**
```json
{
  "url": "...",
  "prediction": "phishing",
  "confidence": 94.2,
  "risk_score": 87,
  "risk_level": "phishing",
  "risk_color": "#ff2d55",
  "explanations": [
    "Suspicious keyword detected: 'login'",
    "Suspicious top-level domain (TLD) detected",
    "No HTTPS — connection is not encrypted"
  ],
  "top_features": [...],
  "model_used": "xgboost",
  "latency_ms": 12.4
}
```

### POST /predict/batch

Send up to 50 URLs in one request.

### GET /health

Returns API/model status.

---

## Chrome Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `chrome_extension/` folder
4. Click the PhishGuard icon to scan the current page

---

## Features Analyzed (28+)

| Category | Features |
|---|---|
| Lexical | URL length, dot count, hyphen count, @ symbol, special chars, entropy, digit ratio |
| Security | HTTPS check, IP in URL, URL shortener, punycode/IDN |
| Content | Suspicious keywords, brand impersonation, suspicious TLD |
| Domain | Age (WHOIS), SSL certificate, subdomain depth, registrar |

---

## Technology Stack

- **Backend**: Python, FastAPI, Uvicorn
- **ML**: Scikit-learn, XGBoost, SHAP, imbalanced-learn
- **URL Analysis**: tldextract, python-whois
- **Frontend**: HTML5, CSS3, Vanilla JS (no framework)
- **Extension**: Chrome Manifest V3

---

## Dataset

Compatible with any CSV containing `url` and `label` (0=legitimate, 1=phishing) columns.

Recommended sources:
- [Phishing Site URLs — Kaggle](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls)
- [UCI Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
