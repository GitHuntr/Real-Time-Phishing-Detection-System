"""
PhishGuard - FastAPI Backend
Real-Time Phishing Detection API
"""

import os
import time
import logging
import urllib.parse
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, validator
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from predictor import get_predictor

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PhishGuard API starting — loading predictor...")
    get_predictor()  # Warm up
    logger.info("PhishGuard API ready.")
    yield
    logger.info("PhishGuard API shutting down.")


# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="Real-Time Phishing URL Detection — powered by ML + SHAP",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Frontend paths
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))

# Mount CSS and JS as static asset directories
if os.path.isdir(frontend_path):
    app.mount("/css", StaticFiles(directory=os.path.join(frontend_path, 'css')), name="css")
    app.mount("/js",  StaticFiles(directory=os.path.join(frontend_path, 'js')),  name="js")


# ─── Request / Response Models ────────────────────────────────────────────────

class PredictRequest(BaseModel):
    url: str
    include_domain_features: bool = False
    vt_api_key: Optional[str] = None

    @validator('url')
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 2000:
            raise ValueError("URL exceeds maximum length of 2000 characters")
        # Add scheme if missing for validation
        test_url = v if v.startswith(('http://', 'https://')) else f'http://{v}'
        try:
            result = urllib.parse.urlparse(test_url)
            if not result.netloc:
                raise ValueError("Invalid URL format")
        except Exception:
            raise ValueError("Invalid URL format")
        return v


class FeatureDetail(BaseModel):
    name: str
    label: str
    value: float
    shap_value: float
    direction: str
    description: str


class PredictResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_score: int
    risk_level: str
    risk_color: str
    explanations: List[str]
    top_features: List[dict]
    model_used: str
    latency_ms: float
    timestamp: str


class BatchPredictRequest(BaseModel):
    urls: List[str]
    include_domain_features: bool = False

    @validator('urls')
    def validate_urls(cls, v):
        if not v:
            raise ValueError("URLs list cannot be empty")
        if len(v) > 50:
            raise ValueError("Maximum 50 URLs per batch request")
        return v


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: str
    version: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    index = os.path.join(frontend_path, 'index.html')
    if os.path.isfile(index):
        return FileResponse(index, media_type='text/html')
    return {"service": "PhishGuard API", "version": "1.0.0", "docs": "/docs"}


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint."""
    predictor = get_predictor()
    model_name = "none"
    if predictor.is_loaded() and predictor.artifact:
        model_name = predictor.artifact.get("metadata", {}).get("model_name", "unknown")

    return HealthResponse(
        status="healthy",
        model_loaded=predictor.is_loaded(),
        model_name=model_name,
        version="1.0.0",
    )


@app.post("/predict", response_model=PredictResponse, tags=["Detection"])
@limiter.limit("30/minute")
async def predict_url(request: Request, body: PredictRequest):
    """
    Analyze a URL for phishing indicators.

    - **url**: The URL to analyze
    - **include_domain_features**: Include WHOIS/SSL analysis (slower, more accurate)
    - **vt_api_key**: Optional VirusTotal API key for additional analysis

    Returns a prediction with confidence score, risk score, and SHAP explanations.
    """
    try:
        predictor = get_predictor()
        result = predictor.predict(
            url=body.url,
            include_domain_features=body.include_domain_features,
            vt_api_key=body.vt_api_key,
        )
        return PredictResponse(**{
            k: result[k]
            for k in PredictResponse.__fields__.keys()
            if k in result
        })
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Prediction error for URL '{body.url}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal prediction error")


@app.post("/predict/batch", tags=["Detection"])
@limiter.limit("10/minute")
async def predict_batch(request: Request, body: BatchPredictRequest):
    """
    Analyze multiple URLs in a single request (max 50).
    Domain features are not available in batch mode.
    """
    predictor = get_predictor()
    results = []

    for url in body.urls:
        try:
            result = predictor.predict(
                url=url,
                include_domain_features=False,
            )
            results.append({
                "url": url,
                "prediction": result["prediction"],
                "risk_score": result["risk_score"],
                "confidence": result["confidence"],
                "explanations": result["explanations"][:3],
            })
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e),
                "prediction": "error",
                "risk_score": -1,
                "confidence": 0,
                "explanations": [],
            })

    return {"results": results, "count": len(results)}


@app.get("/features/{url:path}", tags=["Detection"])
@limiter.limit("20/minute")
async def get_features(request: Request, url: str):
    """Get extracted features for a URL without running ML prediction."""
    from feature_extractor import extract_lexical_features, normalize_url

    try:
        normalized = normalize_url(urllib.parse.unquote(url))
        features = extract_lexical_features(normalized)
        return {"url": url, "normalized_url": normalized, "features": features}
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/model/info", tags=["System"])
async def model_info():
    """Get information about the loaded model."""
    predictor = get_predictor()
    if not predictor.is_loaded():
        return {"loaded": False, "mode": "rule-based fallback"}

    metadata = predictor.artifact.get("metadata", {})
    return {
        "loaded": True,
        "model_name": metadata.get("model_name"),
        "f1_score": metadata.get("f1_score"),
        "accuracy": metadata.get("accuracy"),
        "auc": metadata.get("auc"),
        "trained_on": metadata.get("trained_on"),
        "n_features": metadata.get("n_features"),
        "feature_names": predictor.feature_names,
    }


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": "Endpoint not found"})


@app.exception_handler(500)
async def server_error(request: Request, exc):
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        workers=1,
    )
