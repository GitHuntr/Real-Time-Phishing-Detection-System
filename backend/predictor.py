"""
PhishGuard - Prediction Engine
Orchestrates feature extraction, ML prediction, SHAP explanation, and risk scoring.
"""

import os
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from feature_extractor import (
    normalize_url, extract_lexical_features,
    extract_domain_features, LEXICAL_FEATURE_NAMES
)
from explainer import PhishGuardExplainer, FEATURE_DESCRIPTIONS
from model_trainer import load_model

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent / "models"

# ─── Labels ───────────────────────────────────────────────────────────────────
LABEL_MAP = {0: "legitimate", 1: "phishing"}
CLASS_CONFIDENCE_THRESHOLDS = {
    "legitimate": 0.0,
    "suspicious": 0.45,
    "phishing": 0.70,
}


# ─── Risk Scorer ──────────────────────────────────────────────────────────────

def compute_risk_score(
    phishing_probability: float,
    features: Dict[str, Any],
    has_ssl: bool
) -> int:
    """
    Compute a 0-100 risk score combining:
      - ML model confidence (70%)
      - Rule-based signals (30%)
    """
    # Base score from model probability
    base_score = phishing_probability * 70

    # Rule-based bonus signals
    bonus = 0
    rule_checks = {
        "has_ip_address": (features.get("has_ip_address", 0), 5),
        "no_https": (not features.get("has_https", 1), 5),
        "has_at_symbol": (features.get("has_at_symbol", 0), 5),
        "brand_in_subdomain": (features.get("brand_in_subdomain", 0), 5),
        "is_url_shortened": (features.get("is_url_shortened", 0), 3),
        "has_suspicious_keyword": (features.get("has_suspicious_keyword", 0), 3),
        "is_suspicious_tld": (features.get("is_suspicious_tld", 0), 2),
        "has_punycode": (features.get("has_punycode", 0), 4),
        "new_domain": (0 < features.get("domain_age_days", -1) <= 30, 4),
    }

    for _, (triggered, weight) in rule_checks.items():
        if triggered:
            bonus += weight

    total_score = min(100, int(base_score + bonus))
    return total_score


def risk_level_from_score(score: int) -> str:
    if score >= 70:
        return "phishing"
    elif score >= 40:
        return "suspicious"
    else:
        return "legitimate"


def risk_color_from_level(level: str) -> str:
    return {"phishing": "#ff2d55", "suspicious": "#ffcc00", "legitimate": "#00ff9f"}.get(level, "#888")


# ─── Predictor Class ──────────────────────────────────────────────────────────

class PhishGuardPredictor:
    def __init__(self, model_path: Optional[str] = None):
        self.artifact = None
        self.model = None
        self.feature_names = LEXICAL_FEATURE_NAMES
        self.explainer = None
        self._loaded = False

        if model_path:
            self.load(model_path)

    def load(self, model_path: str):
        """Load a trained model artifact."""
        try:
            self.artifact = load_model(Path(model_path).name)
            self.model = self.artifact["model"]
            self.feature_names = self.artifact["feature_names"]
            self.explainer = PhishGuardExplainer(self.model, self.feature_names)
            self.explainer.initialize()
            self._loaded = True
            logger.info(f"Model loaded: {self.artifact['metadata'].get('model_name', 'unknown')}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._loaded = False

    def is_loaded(self) -> bool:
        return self._loaded

    def predict(
        self,
        url: str,
        include_domain_features: bool = False,
        vt_api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full prediction pipeline for a URL.
        Returns structured prediction result.
        """
        start_time = datetime.now()

        # Normalize URL
        normalized_url = normalize_url(url)

        # Extract features
        lexical_feats = extract_lexical_features(normalized_url)

        # Domain features (optional — slower due to WHOIS/SSL)
        domain_feats = {}
        if include_domain_features:
            domain_feats = extract_domain_features(normalized_url)

        all_feats = {**lexical_feats, **domain_feats}

        # Build feature vector
        feature_vector = []
        for feat_name in self.feature_names:
            feature_vector.append(all_feats.get(feat_name, 0))

        X = pd.DataFrame([feature_vector], columns=self.feature_names)

        # ML prediction
        if self._loaded and self.model is not None:
            proba = self.model.predict_proba(X)[0]
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        else:
            # Fallback: rule-based scoring
            phishing_prob = self._rule_based_probability(all_feats)

        # Risk score
        risk_score = compute_risk_score(phishing_prob, all_feats, bool(all_feats.get("has_ssl_certificate", 0)))
        risk_level = risk_level_from_score(risk_score)

        # Confidence
        if risk_level == "phishing":
            confidence = round(min(phishing_prob * 100, 99.9), 1)
        elif risk_level == "suspicious":
            confidence = round(phishing_prob * 100, 1)
        else:
            confidence = round((1 - phishing_prob) * 100, 1)

        # SHAP Explanations
        if self.explainer:
            shap_explanations = self.explainer.explain(X)
            human_explanations = self.explainer.get_human_readable_explanations(shap_explanations)
        else:
            shap_explanations = []
            human_explanations = self._rule_based_explanations(all_feats)

        # Remove duplicates
        human_explanations = list(dict.fromkeys(human_explanations))

        # Top SHAP features for radar/bar chart
        top_features = []
        for exp in shap_explanations[:6]:
            feat = exp["feature"]
            top_features.append({
                "name": feat,
                "label": feat.replace("_", " ").title(),
                "value": exp["value"],
                "shap_value": round(abs(exp["shap_value"]) * 100, 2),
                "direction": exp["direction"],
                "description": FEATURE_DESCRIPTIONS.get(feat, ("", ""))[0 if exp["direction"] == "phishing" else 1],
            })

        elapsed_ms = round((datetime.now() - start_time).total_seconds() * 1000, 1)

        return {
            "url": url,
            "normalized_url": normalized_url,
            "prediction": risk_level,
            "phishing_probability": round(phishing_prob, 4),
            "confidence": confidence,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_color": risk_color_from_level(risk_level),
            "explanations": human_explanations[:6],
            "top_features": top_features,
            "features": {k: round(v, 4) if isinstance(v, float) else v for k, v in all_feats.items()},
            "model_used": self.artifact["metadata"].get("model_name", "rule-based") if self._loaded else "rule-based",
            "latency_ms": elapsed_ms,
            "timestamp": start_time.isoformat(),
        }

    def _rule_based_probability(self, features: Dict) -> float:
        """Estimate phishing probability from rules when no model is loaded."""
        score = 0
        checks = [
            features.get("has_ip_address", 0),
            1 - features.get("has_https", 1),
            features.get("has_at_symbol", 0),
            features.get("brand_in_subdomain", 0),
            features.get("is_url_shortened", 0),
            features.get("has_suspicious_keyword", 0),
            features.get("is_suspicious_tld", 0),
            features.get("has_punycode", 0),
            int(features.get("url_length", 0) > 75),
            int(features.get("subdomain_count", 0) > 2),
        ]
        score = sum(checks) / len(checks)
        return min(score, 0.99)

    def _rule_based_explanations(self, features: Dict) -> list:
        from explainer import PHISHING_THRESHOLD_RULES, FEATURE_DESCRIPTIONS
        explanations = []
        for feat, fn in PHISHING_THRESHOLD_RULES.items():
            val = features.get(feat, 0)
            if fn(val) and feat in FEATURE_DESCRIPTIONS:
                explanations.append(FEATURE_DESCRIPTIONS[feat][0])
        return explanations


# ─── Singleton predictor ──────────────────────────────────────────────────────

_predictor_instance: Optional[PhishGuardPredictor] = None


def get_predictor() -> PhishGuardPredictor:
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = PhishGuardPredictor()
        # Try to load default model
        default_model = MODELS_DIR / "phishguard_model.pkl"
        if default_model.exists():
            _predictor_instance.load(str(default_model))
        else:
            logger.warning("No trained model found. Using rule-based fallback.")
    return _predictor_instance
