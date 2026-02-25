"""
PhishGuard - FastAPI Backend
Real-Time Phishing Detection API
"""

import os
import io
import csv
import time
import logging
import urllib.parse
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, validator
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from predictor import get_predictor

# ─── Environment Config ────────────────────────────────────────────────────────

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ALLOWED_ORIGINS  = os.getenv("ALLOWED_ORIGINS", "*").split(",")
MAX_UPLOAD_URLS  = int(os.getenv("MAX_UPLOAD_URLS",  "500"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))  # 5 MB

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


# ─── Upload File Parser ────────────────────────────────────────────────────────

def _parse_upload(raw: bytes, filename: str) -> List[str]:
    """Extract URLs from uploaded .txt or .csv content."""
    text = raw.decode("utf-8", errors="replace")
    ext  = (filename or "").rsplit(".", 1)[-1].lower()

    if ext == "csv":
        reader    = csv.DictReader(io.StringIO(text))
        fields    = reader.fieldnames or []
        url_field = next(
            (f for f in fields if "url" in f.lower()),
            fields[0] if fields else None,
        )
        urls = []
        for row in reader:
            val = row.get(url_field, "").strip() if url_field else ""
            if val:
                urls.append(val)
        return urls

    # Plain text: one URL per line
    return [line.strip() for line in text.splitlines() if line.strip()]


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

# CORS — controlled via ALLOWED_ORIGINS env var
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
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
    normalized_url: str = ""
    prediction: str
    confidence: float
    risk_score: int
    risk_level: str
    risk_color: str
    explanations: List[str]
    top_features: List[dict]
    features: dict = {}
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
    predictor  = get_predictor()
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
    results   = []

    for url in body.urls:
        try:
            result = predictor.predict(url=url, include_domain_features=False)
            results.append({
                "url":          url,
                "prediction":   result["prediction"],
                "risk_score":   result["risk_score"],
                "confidence":   result["confidence"],
                "explanations": result["explanations"][:3],
            })
        except Exception as e:
            results.append({
                "url":          url,
                "error":        str(e),
                "prediction":   "error",
                "risk_score":   -1,
                "confidence":   0,
                "explanations": [],
            })

    return {"results": results, "count": len(results)}


@app.post("/predict/upload", tags=["Detection"])
@limiter.limit("5/minute")
async def predict_upload(request: Request, file: UploadFile = File(...)):
    """
    Upload a .txt or .csv file containing URLs (one per line or URL column).

    - **.txt**: One URL per line
    - **.csv**: Must contain a column with "url" in its name (or uses first column)
    - Max file size: 5 MB
    - Max URLs: 500

    Returns batch scan results with summary statistics.
    """
    filename = file.filename or ""
    ext      = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in ("txt", "csv"):
        raise HTTPException(
            status_code=422,
            detail="Only .txt and .csv files are supported",
        )

    raw = await file.read()

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {MAX_UPLOAD_BYTES // (1024*1024)} MB",
        )

    try:
        urls = _parse_upload(raw, filename)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse file: {e}")

    if not urls:
        raise HTTPException(status_code=422, detail="No URLs found in file")

    # Deduplicate while preserving order
    seen, deduped = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    if len(deduped) > MAX_UPLOAD_URLS:
        raise HTTPException(
            status_code=422,
            detail=f"File contains {len(deduped)} URLs — maximum is {MAX_UPLOAD_URLS}",
        )

    predictor = get_predictor()
    results   = []
    stats     = {"phishing": 0, "suspicious": 0, "legitimate": 0, "error": 0}

    for url in deduped:
        try:
            result = predictor.predict(url=url, include_domain_features=False)
            pred   = result["prediction"]
            stats[pred] = stats.get(pred, 0) + 1
            results.append({
                "url":          url,
                "prediction":   pred,
                "risk_score":   result["risk_score"],
                "confidence":   result["confidence"],
                "risk_level":   result["risk_level"],
            })
        except Exception as e:
            stats["error"] += 1
            results.append({
                "url":        url,
                "prediction": "error",
                "risk_score": -1,
                "confidence": 0,
                "risk_level": "error",
                "error":      str(e),
            })

    threat_count = stats["phishing"] + stats["suspicious"]

    return {
        "filename":      filename,
        "total":         len(results),
        "threat_count":  threat_count,
        "stats":         stats,
        "results":       results,
    }


@app.get("/features/{url:path}", tags=["Detection"])
@limiter.limit("20/minute")
async def get_features(request: Request, url: str):
    """Get extracted features for a URL without running ML prediction."""
    from feature_extractor import extract_lexical_features, normalize_url

    try:
        normalized = normalize_url(urllib.parse.unquote(url))
        features   = extract_lexical_features(normalized)
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
        "loaded":        True,
        "model_name":    metadata.get("model_name"),
        "f1_score":      metadata.get("f1_score"),
        "accuracy":      metadata.get("accuracy"),
        "auc":           metadata.get("auc"),
        "trained_on":    metadata.get("trained_on"),
        "n_features":    metadata.get("n_features"),
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
        host  = os.getenv("HOST",  "0.0.0.0"),
        port  = int(os.getenv("PORT", "8000")),
        reload= os.getenv("RELOAD", "true").lower() == "true",
        workers=1,
    )
