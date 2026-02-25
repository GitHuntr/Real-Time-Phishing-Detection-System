"""
PhishGuard - SHAP Explainability Engine
Generates human-readable explanations for phishing predictions using SHAP.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
import shap

# ─── Human-readable feature descriptions ─────────────────────────────────────

FEATURE_DESCRIPTIONS = {
    "url_length": ("URL is unusually long", "URL length is normal"),
    "domain_length": ("Domain name is suspiciously long", "Domain name length is normal"),
    "path_length": ("URL path is very long", "URL path length is normal"),
    "dot_count": ("Excessive dots in URL", "Normal number of dots"),
    "hyphen_count": ("Multiple hyphens detected in URL", "Normal hyphen usage"),
    "at_count": ("'@' symbol found — may redirect to different domain", "No '@' symbol"),
    "question_mark_count": ("Multiple query parameters — possible obfuscation", "Normal query parameters"),
    "and_count": ("Excessive query parameters", "Normal query parameters"),
    "equal_count": ("Multiple assignment operators in query", "Normal query syntax"),
    "underscore_count": ("Unusual underscores detected", "Normal underscore usage"),
    "slash_count": ("Excessive forward slashes — possible path manipulation", "Normal path depth"),
    "percent_count": ("Percent-encoded characters detected — possible obfuscation", "No obfuscation detected"),
    "has_ip_address": ("IP address used instead of domain name", "Domain name used (not IP)"),
    "has_https": ("No HTTPS — connection is not encrypted", "HTTPS certificate present"),
    "has_at_symbol": ("'@' symbol in URL — browser ignores everything before it", "No '@' symbol present"),
    "has_double_slash_redirect": ("Double slash redirect detected in path", "No double slash redirect"),
    "has_hyphen_in_domain": ("Hyphen in domain name — common in phishing", "No hyphen in domain"),
    "subdomain_count": ("Excessive number of subdomains", "Normal subdomain depth"),
    "suspicious_keyword_count": ("Suspicious keywords found (login, verify, secure, etc.)", "No suspicious keywords"),
    "has_suspicious_keyword": ("Phishing keyword detected in URL", "No phishing keywords found"),
    "brand_in_subdomain": ("Brand name impersonation detected in subdomain", "No brand impersonation"),
    "brand_in_path": ("Brand name impersonation detected in path", "No brand impersonation"),
    "is_suspicious_tld": ("Suspicious top-level domain (TLD) detected", "TLD appears legitimate"),
    "domain_entropy": ("Domain name appears randomly generated", "Domain name appears human-readable"),
    "digit_ratio": ("High proportion of digits — possibly randomly generated", "Normal digit usage"),
    "hostname_dot_count": ("Too many dots in hostname", "Normal hostname structure"),
    "has_punycode": ("Punycode/internationalized domain — possible homograph attack", "No punycode detected"),
    "is_url_shortened": ("URL shortener detected — hides true destination", "Full URL visible"),
    "domain_age_days": ("Domain registered recently — less than 30 days old", "Domain has established history"),
    "domain_expiry_days": ("Domain expires soon — low commitment by registrant", "Domain has long registration"),
    "has_ssl_certificate": ("No valid SSL certificate found", "Valid SSL certificate present"),
    "ssl_age_days": ("SSL certificate is very new", "SSL certificate has established history"),
    "registrar_known": ("Unknown or no registrar information", "Domain registered with known registrar"),
    "domain_registered": ("Domain registration information unavailable", "Domain registration information found"),
}

PHISHING_THRESHOLD_RULES = {
    "url_length": lambda v: v > 75,
    "dot_count": lambda v: v > 5,
    "has_ip_address": lambda v: v == 1,
    "has_https": lambda v: v == 0,
    "has_at_symbol": lambda v: v == 1,
    "subdomain_count": lambda v: v > 2,
    "has_suspicious_keyword": lambda v: v == 1,
    "brand_in_subdomain": lambda v: v == 1,
    "domain_entropy": lambda v: v > 3.5,
    "is_url_shortened": lambda v: v == 1,
    "has_punycode": lambda v: v == 1,
    "domain_age_days": lambda v: 0 <= v <= 30,
    "has_ssl_certificate": lambda v: v == 0,
    "is_suspicious_tld": lambda v: v == 1,
    "percent_count": lambda v: v > 3,
}


# ─── SHAP Explainer ───────────────────────────────────────────────────────────

class PhishGuardExplainer:
    def __init__(self, model, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self._explainer = None
        self._background_data = None

    def initialize(self, background_data: Optional[np.ndarray] = None):
        """Initialize SHAP explainer with optional background data."""
        try:
            if background_data is not None:
                self._background_data = background_data
                # Use TreeExplainer for tree-based models
                if hasattr(self._get_classifier(), 'feature_importances_'):
                    self._explainer = shap.TreeExplainer(self._get_classifier())
                else:
                    self._explainer = shap.LinearExplainer(
                        self._get_classifier(),
                        background_data
                    )
            else:
                # Fallback: TreeExplainer for XGBoost/RF
                clf = self._get_classifier()
                if hasattr(clf, 'feature_importances_'):
                    self._explainer = shap.TreeExplainer(clf)
        except Exception as e:
            self._explainer = None

    def _get_classifier(self):
        """Extract actual classifier from pipeline if needed."""
        if hasattr(self.model, 'named_steps'):
            return self.model.named_steps.get('clf', self.model)
        return self.model

    def explain(self, features: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Generate SHAP-based explanations for a single prediction.
        Returns list of contributing factors sorted by impact.
        """
        explanations = []

        if self._explainer is not None:
            try:
                # Transform through pipeline scaler if present
                if hasattr(self.model, 'named_steps') and 'scaler' in self.model.named_steps:
                    X_transformed = self.model.named_steps['scaler'].transform(features)
                else:
                    X_transformed = features.values

                shap_values = self._explainer.shap_values(X_transformed)

                # For binary classification, use phishing class (index 1)
                if isinstance(shap_values, list) and len(shap_values) > 1:
                    sv = shap_values[1][0]
                elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2:
                    sv = shap_values[0]
                else:
                    sv = shap_values[0] if isinstance(shap_values, list) else shap_values

                for i, (feat, val) in enumerate(zip(self.feature_names, features.iloc[0])):
                    shap_val = float(sv[i]) if i < len(sv) else 0.0
                    explanations.append({
                        "feature": feat,
                        "value": float(val),
                        "shap_value": shap_val,
                        "impact": "high" if abs(shap_val) > 0.1 else "medium" if abs(shap_val) > 0.05 else "low",
                        "direction": "phishing" if shap_val > 0 else "legitimate",
                    })

                explanations.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
                return explanations[:10]

            except Exception:
                pass

        # Fallback: rule-based explanations
        return self._rule_based_explain(features)

    def _rule_based_explain(self, features: pd.DataFrame) -> List[Dict[str, Any]]:
        """Fallback rule-based explanation when SHAP fails."""
        explanations = []
        row = features.iloc[0]

        for feat, threshold_fn in PHISHING_THRESHOLD_RULES.items():
            if feat in row.index:
                val = row[feat]
                triggered = threshold_fn(val)
                if triggered:
                    explanations.append({
                        "feature": feat,
                        "value": float(val),
                        "shap_value": 0.2,  # placeholder for display
                        "impact": "high",
                        "direction": "phishing",
                    })

        return explanations[:10]

    def get_human_readable_explanations(self, shap_explanations: List[Dict]) -> List[str]:
        """Convert SHAP explanations to human-readable strings."""
        readable = []
        for exp in shap_explanations:
            feat = exp["feature"]
            val = exp["value"]
            direction = exp["direction"]

            if feat in FEATURE_DESCRIPTIONS:
                desc_phishing, desc_legit = FEATURE_DESCRIPTIONS[feat]
                if direction == "phishing":
                    readable.append(desc_phishing)
                else:
                    readable.append(desc_legit)

        # Deduplicate while preserving order
        seen = set()
        result = []
        for item in readable:
            if item not in seen:
                seen.add(item)
                result.append(item)

        return result
