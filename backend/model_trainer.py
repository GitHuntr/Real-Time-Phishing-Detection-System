"""
PhishGuard - Model Trainer
Trains, evaluates, and saves the best ML model for phishing URL detection.

Usage:
    python model_trainer.py --data ../data/dataset.csv --output phishguard_model.pkl
"""

import os
import json
import pickle
import logging
import warnings
import argparse
from pathlib import Path
from typing import Tuple, Dict

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    f1_score, accuracy_score, precision_score,
    recall_score, roc_auc_score, classification_report,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import xgboost as xgb
from imblearn.over_sampling import SMOTE

from feature_extractor import LEXICAL_FEATURE_NAMES, extract_lexical_features, normalize_url

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


def get_models():
    return {
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                C=1.0, max_iter=1000, class_weight="balanced", random_state=42
            )),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=15, min_samples_split=5,
            class_weight="balanced", n_jobs=-1, random_state=42,
        ),
        "xgboost": xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42, verbosity=0,
        ),
    }


def load_dataset(path: str) -> Tuple[pd.Series, pd.Series]:
    log.info(f"Loading dataset: {path}")
    df = pd.read_csv(path)
    df.columns = df.columns.str.lower().str.strip()

    if "status" in df.columns and "label" not in df.columns:
        df["label"] = df["status"].map({"legitimate": 0, "phishing": 1, "defacement": 1, "malware": 1})

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must have 'url' and 'label' columns")

    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    log.info(f"Loaded {len(df)} samples. Distribution: {df['label'].value_counts().to_dict()}")
    return df["url"], df["label"]


def build_features(urls: pd.Series) -> pd.DataFrame:
    import multiprocessing

    def safe_extract(url):
        try:
            return extract_lexical_features(normalize_url(str(url)))
        except Exception:
            return {k: 0 for k in LEXICAL_FEATURE_NAMES}

    log.info(f"Extracting features for {len(urls)} URLs...")
    with multiprocessing.Pool(max(1, multiprocessing.cpu_count() - 1)) as pool:
        feats = pool.map(safe_extract, urls)

    df = pd.DataFrame(feats)
    for col in LEXICAL_FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0
    return df[LEXICAL_FEATURE_NAMES]


def train(X: pd.DataFrame, y: pd.Series, smote: bool = True) -> Dict:
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    if smote and y_tr.value_counts().min() > 5:
        log.info("Applying SMOTE...")
        k = min(5, y_tr.value_counts().min() - 1)
        X_tr, y_tr = SMOTE(random_state=42, k_neighbors=k).fit_resample(X_tr, y_tr)

    results = {}
    best_name, best_f1 = None, 0.0

    for name, model in get_models().items():
        log.info(f"Training {name}...")
        model.fit(X_tr, y_tr)
        y_pred = model.predict(X_te)
        y_prob = model.predict_proba(X_te)[:, 1]

        f1  = f1_score(y_te, y_pred, average="weighted")
        acc = accuracy_score(y_te, y_pred)
        auc = roc_auc_score(y_te, y_prob)

        results[name] = {
            "model": model,
            "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "precision": round(precision_score(y_te, y_pred, average="weighted"), 4),
            "recall": round(recall_score(y_te, y_pred, average="weighted"), 4),
            "auc": round(auc, 4),
            "report": classification_report(y_te, y_pred),
        }
        log.info(f"  {name}: F1={f1:.4f}  ACC={acc:.4f}  AUC={auc:.4f}")
        if f1 > best_f1:
            best_f1, best_name = f1, name

    log.info(f"Best model: {best_name} (F1={best_f1:.4f})")
    return results, best_name


def save_model(model, metadata: dict, filename: str):
    artifact = {"model": model, "feature_names": LEXICAL_FEATURE_NAMES,
                "metadata": metadata, "label_map": {0: "legitimate", 1: "phishing"}}
    path = MODELS_DIR / filename
    with open(path, "wb") as f:
        pickle.dump(artifact, f)
    log.info(f"Model saved: {path}")
    return path


def load_model(filename: str = "phishguard_model.pkl"):
    with open(MODELS_DIR / filename, "rb") as f:
        return pickle.load(f)


def main():
    parser = argparse.ArgumentParser(description="PhishGuard Model Trainer")
    parser.add_argument("--data",     required=True, help="Path to dataset CSV")
    parser.add_argument("--output",   default="phishguard_model.pkl")
    parser.add_argument("--no-smote", action="store_true")
    args = parser.parse_args()

    urls, labels = load_dataset(args.data)
    X = build_features(urls)
    y = labels.reset_index(drop=True)

    results, best_name = train(X, y, smote=not args.no_smote)

    # Print comparison table
    print("\n" + "=" * 68)
    print(f"{'MODEL':<25} {'F1':>8} {'ACC':>8} {'PREC':>8} {'REC':>8} {'AUC':>8}")
    print("=" * 68)
    for name, r in results.items():
        tag = " <-- BEST" if name == best_name else ""
        print(f"{name:<25} {r['f1']:>8.4f} {r['accuracy']:>8.4f} "
              f"{r['precision']:>8.4f} {r['recall']:>8.4f} {r['auc']:>8.4f}{tag}")
    print("=" * 68)
    print(f"\nReport ({best_name}):\n{results[best_name]['report']}")

    best = results[best_name]
    meta = {
        "model_name": best_name,
        "f1_score":   best["f1"],
        "accuracy":   best["accuracy"],
        "auc":        best["auc"],
        "trained_on": str(pd.Timestamp.now()),
        "n_features": len(LEXICAL_FEATURE_NAMES),
        "feature_names": LEXICAL_FEATURE_NAMES,
    }
    save_model(best["model"], meta, args.output)

    # Save metrics JSON
    report = {k: {kk: vv for kk, vv in v.items() if kk != "model"} for k, v in results.items()}
    with open(MODELS_DIR / "training_metrics.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nAll done. Run the API: uvicorn main:app --reload")


if __name__ == "__main__":
    main()
