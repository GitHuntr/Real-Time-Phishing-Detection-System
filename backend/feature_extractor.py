"""
PhishGuard - Feature Extraction Engine
Extracts lexical and domain-based features from URLs for ML classification.
"""

import re
import math
import ssl
import socket
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional

import tldextract

# ─── Suspicious keyword lists ────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "banking", "paypal", "ebay", "amazon",
    "apple", "microsoft", "google", "facebook", "instagram", "twitter",
    "password", "credential", "wallet", "crypto", "bitcoin", "urgent",
    "alert", "suspended", "limited", "access", "click", "free", "prize",
    "winner", "congratulations", "bonus", "offer", "deal", "buy", "cheap",
]

BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
]

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tr.im', 'short.link', 'rb.gy',
]

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'tk', 'ml', 'ga', 'cf',
    'gq', 'pw', 'cc', 'info', 'biz', 'cn', 'ru',
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url
    return urllib.parse.unquote(url)


def _string_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def extract_lexical_features(url: str) -> Dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    domain_info = tldextract.extract(url)

    hostname = parsed.netloc or ''
    path = parsed.path or ''

    url_length = len(url)
    domain_length = len(domain_info.domain)
    path_length = len(path)

    dot_count = url.count('.')
    hyphen_count = url.count('-')
    at_count = url.count('@')
    question_mark_count = url.count('?')
    and_count = url.count('&')
    equal_count = url.count('=')
    underscore_count = url.count('_')
    slash_count = url.count('/')
    percent_count = url.count('%')

    has_ip_address = int(bool(re.match(
        r'^(\d{1,3}\.){3}\d{1,3}$', hostname.split(':')[0]
    )))

    has_https = int(parsed.scheme.lower() == 'https')
    has_at_symbol = int('@' in url)
    has_double_slash_redirect = int('//' in path)
    has_hyphen_in_domain = int('-' in domain_info.domain)

    subdomain = domain_info.subdomain
    subdomain_count = len(subdomain.split('.')) if subdomain else 0

    url_lower = url.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_keyword = int(suspicious_keyword_count > 0)

    brand_in_subdomain = int(any(b in subdomain.lower() for b in BRAND_NAMES))
    brand_in_path = int(any(b in path.lower() for b in BRAND_NAMES))

    tld = domain_info.suffix.lower() if domain_info.suffix else ''
    is_suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    domain_entropy = round(_string_entropy(domain_info.domain), 4)
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = round(digit_count / max(url_length, 1), 4)
    hostname_dot_count = hostname.count('.')

    has_punycode = int('xn--' in url.lower())
    is_url_shortened = int(any(s in url_lower for s in SHORTENER_DOMAINS))

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_count": at_count,
        "question_mark_count": question_mark_count,
        "and_count": and_count,
        "equal_count": equal_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "percent_count": percent_count,
        "has_ip_address": has_ip_address,
        "has_https": has_https,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "subdomain_count": subdomain_count,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_suspicious_keyword": has_suspicious_keyword,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "is_suspicious_tld": is_suspicious_tld,
        "domain_entropy": domain_entropy,
        "digit_ratio": digit_ratio,
        "hostname_dot_count": hostname_dot_count,
        "has_punycode": has_punycode,
        "is_url_shortened": is_url_shortened,
    }


def extract_domain_features(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Extract WHOIS and SSL-based domain features (slower — requires network)."""
    domain_info = tldextract.extract(url)
    registered_domain = domain_info.registered_domain

    features = {
        "domain_age_days": -1,
        "domain_expiry_days": -1,
        "has_ssl_certificate": 0,
        "ssl_age_days": -1,
        "registrar_known": 0,
        "domain_registered": 0,
    }

    if not registered_domain:
        return features

    try:
        import whois
        w = whois.whois(registered_domain)
        features["domain_registered"] = 1

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            age = (datetime.now() - creation_date).days
            features["domain_age_days"] = max(age, 0)

        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if isinstance(expiry_date, datetime):
            expiry = (expiry_date - datetime.now()).days
            features["domain_expiry_days"] = max(expiry, 0)

        if w.registrar:
            features["registrar_known"] = 1
    except Exception:
        pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((registered_domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=registered_domain) as ssock:
                cert = ssock.getpeercert()
                features["has_ssl_certificate"] = 1
                not_before = ssl.cert_time_to_seconds(cert['notBefore'])
                cert_age = (datetime.now().timestamp() - not_before) / 86400
                features["ssl_age_days"] = int(cert_age)
    except Exception:
        pass

    return features


def query_virustotal(url: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    if not api_key:
        return {"vt_malicious_count": 0, "vt_suspicious_count": 0, "vt_available": 0}
    try:
        import hashlib
        import requests
        url_id = hashlib.sha256(url.encode()).hexdigest()
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key}, timeout=10
        )
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return {
                "vt_malicious_count": stats.get('malicious', 0),
                "vt_suspicious_count": stats.get('suspicious', 0),
                "vt_available": 1,
            }
    except Exception:
        pass
    return {"vt_malicious_count": 0, "vt_suspicious_count": 0, "vt_available": 0}


def extract_all_features(
    url: str,
    include_domain: bool = True,
    vt_api_key: Optional[str] = None
) -> Dict[str, Any]:
    normalized = normalize_url(url)
    features = {}
    features.update(extract_lexical_features(normalized))
    if include_domain:
        features.update(extract_domain_features(normalized))
    if vt_api_key:
        features.update(query_virustotal(normalized, vt_api_key))
    return features


# ─── Ordered feature name lists ────────────────────────────────────────────

LEXICAL_FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "dot_count",
    "hyphen_count", "at_count", "question_mark_count", "and_count",
    "equal_count", "underscore_count", "slash_count", "percent_count",
    "has_ip_address", "has_https", "has_at_symbol",
    "has_double_slash_redirect", "has_hyphen_in_domain",
    "subdomain_count", "suspicious_keyword_count", "has_suspicious_keyword",
    "brand_in_subdomain", "brand_in_path", "is_suspicious_tld",
    "domain_entropy", "digit_ratio", "hostname_dot_count",
    "has_punycode", "is_url_shortened",
]

DOMAIN_FEATURE_NAMES = [
    "domain_age_days", "domain_expiry_days", "has_ssl_certificate",
    "ssl_age_days", "registrar_known", "domain_registered",
]

ALL_FEATURE_NAMES = LEXICAL_FEATURE_NAMES + DOMAIN_FEATURE_NAMES
