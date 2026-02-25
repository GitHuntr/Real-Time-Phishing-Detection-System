/**
 * PhishGuard — Frontend Application
 * Real-Time Phishing Detection Dashboard
 */

'use strict';

// ─── Config ────────────────────────────────────────────────────────────────
// Auto-detect API base: same origin when served by FastAPI, fallback for file:// dev
const API_BASE = (location.protocol === 'file:')
  ? 'http://localhost:8000'
  : window.location.origin;

// ─── State ─────────────────────────────────────────────────────────────────
const state = {
  scanning: false,
  history: JSON.parse(localStorage.getItem('pg_history') || '[]'),
};

// ─── DOM References ────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const urlInput         = $('url-input');
const scanBtn          = $('scan-btn');
const resultsPanel     = $('results-panel');
const errorBanner      = $('error-banner');
const scanProgress     = $('scan-progress');
const historySection   = $('history-section');
const historyBody      = $('history-body');

// Verdict card elements
const verdictCard      = $('verdict-card');
const verdictBadge     = $('verdict-badge');
const verdictIcon      = $('verdict-icon');
const verdictText      = $('verdict-text');
const gaugeFill        = $('gauge-fill');
const riskScoreNum     = $('risk-score-number');
const confidenceBar    = $('confidence-bar');
const confidenceVal    = $('confidence-val');
const modelUsed        = $('model-used');
const latencyVal       = $('latency-val');
const timestampVal     = $('timestamp-val');

// Details
const urlDisplay       = $('url-display');
const urlParts         = $('url-parts');
const explanationsList = $('explanations-list');
const featureBars      = $('feature-bars');
const threatGrid       = $('threat-grid');
const domainToggle     = $('domain-toggle');

// Progress stages
const stages = {
  extract: $('stage-extract'),
  model:   $('stage-model'),
  shap:    $('stage-shap'),
  score:   $('stage-score'),
};


// ─── Particle Canvas ───────────────────────────────────────────────────────
(function initParticles() {
  const canvas = $('particle-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let particles = [];
  let animFrame;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  class Particle {
    constructor() {
      this.reset();
    }
    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.size = Math.random() * 1.5 + 0.5;
      this.speedX = (Math.random() - 0.5) * 0.4;
      this.speedY = (Math.random() - 0.5) * 0.4;
      this.opacity = Math.random() * 0.5 + 0.1;
      this.color = Math.random() > 0.7 ? '#00e5ff' : '#00ff9f';
    }
    update() {
      this.x += this.speedX;
      this.y += this.speedY;
      if (this.x < 0 || this.x > canvas.width || this.y < 0 || this.y > canvas.height) {
        this.reset();
      }
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.globalAlpha = this.opacity;
      ctx.fill();
    }
  }

  function init() {
    particles = Array.from({ length: 80 }, () => new Particle());
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.globalAlpha = 1;

    // Draw connections
    particles.forEach((p1, i) => {
      particles.slice(i + 1).forEach(p2 => {
        const dx = p1.x - p2.x, dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(0, 229, 255, ${0.15 * (1 - dist / 120)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      });
    });

    particles.forEach(p => { p.update(); p.draw(); });
    ctx.globalAlpha = 1;
    animFrame = requestAnimationFrame(animate);
  }

  resize();
  init();
  animate();
  window.addEventListener('resize', () => { resize(); init(); });
})();


// ─── Example URL chips ─────────────────────────────────────────────────────
document.querySelectorAll('.example-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.url;
    urlInput.focus();
  });
});


// ─── Scan Flow ─────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', startScan);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

async function startScan() {
  const url = urlInput.value.trim();
  if (!url || state.scanning) return;

  hideError();
  state.scanning = true;
  setScanningUI(true);
  showScanProgress();

  try {
    await simulateStages();

    const includeDomain = domainToggle && domainToggle.checked;
    const response = await fetchPrediction(url, includeDomain);

    renderResults(response);
    addToHistory(response);
    renderHistory();

  } catch (err) {
    showError(err.message || 'Failed to analyze URL. Ensure the API server is running.');
  } finally {
    state.scanning = false;
    setScanningUI(false);
    hideScanProgress();
  }
}


// ─── API Call ──────────────────────────────────────────────────────────────
async function fetchPrediction(url, includeDomain = false) {
  const resp = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, include_domain_features: includeDomain }),
    signal: AbortSignal.timeout(30000),
  });

  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data.detail || `HTTP ${resp.status}`);
  }

  return resp.json();
}


// ─── Render Results ────────────────────────────────────────────────────────
function renderResults(data) {
  const level = data.risk_level || data.prediction;

  // Verdict card
  setVerdictClass(level);
  renderGauge(data.risk_score, level);
  renderVerdict(level);
  renderConfidence(data.confidence, level);
  renderMeta(data);

  // URL breakdown
  renderURLParts(data.normalized_url || data.url);

  // Explanations
  renderExplanations(data.explanations, level);

  // Feature importance bars
  renderFeatureBars(data.top_features || []);

  // Threat indicators
  renderThreatGrid(data.features || {});

  // Show panel
  resultsPanel.classList.add('visible');
  resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setVerdictClass(level) {
  verdictCard.className = `verdict-card ${level}`;
}

function renderGauge(score, level) {
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(score, 100) / 100;
  const offset = circumference * (1 - pct);

  const colorMap = {
    phishing:  '#ff2d55',
    suspicious: '#ffcc00',
    legitimate: '#00ff9f',
  };

  gaugeFill.style.stroke = colorMap[level] || '#00e5ff';
  gaugeFill.setAttribute('stroke-dasharray', circumference.toFixed(1));

  // Animate
  setTimeout(() => {
    gaugeFill.style.strokeDashoffset = offset.toFixed(1);
  }, 100);

  // Animate number
  animateNumber(riskScoreNum, 0, score, 1200);
  riskScoreNum.style.color = colorMap[level] || '#00e5ff';
}

function renderVerdict(level) {
  const config = {
    phishing:  { icon: '⚠',  text: 'Phishing',   cls: 'phishing' },
    suspicious: { icon: '⚡', text: 'Suspicious',  cls: 'suspicious' },
    legitimate: { icon: '✓',  text: 'Safe',        cls: 'legitimate' },
  };
  const c = config[level] || config.legitimate;
  verdictBadge.className = `verdict-badge ${c.cls}`;
  verdictIcon.textContent = c.icon;
  verdictText.textContent = c.text;
}

function renderConfidence(conf, level) {
  confidenceVal.textContent = `${conf.toFixed(1)}%`;
  confidenceBar.className = `bar-fill ${level}`;
  setTimeout(() => { confidenceBar.style.width = `${Math.min(conf, 100)}%`; }, 150);
}

function renderMeta(data) {
  if (modelUsed)    modelUsed.textContent = data.model_used || '—';
  if (latencyVal)   latencyVal.textContent = `${data.latency_ms}ms`;
  if (timestampVal) timestampVal.textContent = new Date(data.timestamp).toLocaleTimeString();
}

function renderURLParts(url) {
  urlDisplay.textContent = url;

  try {
    const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    urlParts.innerHTML = [
      url.startsWith('https') ? `<span class="url-part scheme">HTTPS &#128274;</span>` :
                                `<span class="url-part scheme" style="color:var(--neon-red)">HTTP &#9888;</span>`,
      `<span class="url-part domain">${parsed.hostname}</span>`,
      parsed.pathname !== '/' ? `<span class="url-part path">${parsed.pathname}</span>` : '',
      parsed.search ? `<span class="url-part query">${parsed.search}</span>` : '',
    ].filter(Boolean).join('');
  } catch {
    urlParts.innerHTML = `<span class="url-part domain">${url}</span>`;
  }
}

function renderExplanations(explanations, level) {
  explanationsList.innerHTML = '';

  if (!explanations || explanations.length === 0) {
    explanationsList.innerHTML = `<div class="explanation-item safe">
      <span class="exp-icon">&#10003;</span>
      <span>No significant phishing indicators detected.</span>
    </div>`;
    return;
  }

  explanations.forEach((exp, i) => {
    const cls = level === 'phishing' ? 'risk' : level === 'suspicious' ? 'warn' : 'safe';
    const icon = level === 'phishing' ? '&#9888;' : level === 'suspicious' ? '&#9679;' : '&#10003;';
    const item = document.createElement('div');
    item.className = `explanation-item ${cls}`;
    item.style.animationDelay = `${i * 0.06}s`;
    item.innerHTML = `<span class="exp-icon">${icon}</span><span>${escapeHTML(exp)}</span>`;
    explanationsList.appendChild(item);
  });
}

function renderFeatureBars(topFeatures) {
  featureBars.innerHTML = '';

  if (!topFeatures || topFeatures.length === 0) {
    featureBars.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No feature details available.</div>';
    return;
  }

  const maxShap = Math.max(...topFeatures.map(f => f.shap_value || 0), 1);

  topFeatures.forEach(feat => {
    const pct = ((feat.shap_value || 0) / maxShap * 100).toFixed(1);
    const dir = feat.direction || 'phishing';
    const item = document.createElement('div');
    item.className = 'feature-bar-item';
    item.innerHTML = `
      <div class="feature-bar-label" title="${escapeHTML(feat.label || feat.name)}">${escapeHTML(feat.label || feat.name)}</div>
      <div class="feature-bar-track">
        <div class="feature-bar-fill ${dir}" data-pct="${pct}"></div>
      </div>
      <div class="feature-bar-value">${pct}%</div>
    `;
    featureBars.appendChild(item);
  });

  // Animate after paint
  setTimeout(() => {
    document.querySelectorAll('.feature-bar-fill').forEach(el => {
      el.style.width = el.dataset.pct + '%';
    });
  }, 200);
}

function renderThreatGrid(features) {
  const threatGrid = $('threat-grid');
  if (!threatGrid) return;

  const checks = [
    {
      label: 'HTTPS',
      icon: features.has_https ? '🔒' : '🔓',
      value: features.has_https ? 'Secure' : 'Insecure',
      cls:   features.has_https ? 'ok' : 'danger',
    },
    {
      label: 'IP in URL',
      icon: '🌐',
      value: features.has_ip_address ? 'Yes' : 'No',
      cls:   features.has_ip_address ? 'danger' : 'ok',
    },
    {
      label: '@Symbol',
      icon: '📧',
      value: features.has_at_symbol ? 'Found' : 'Clean',
      cls:   features.has_at_symbol ? 'danger' : 'ok',
    },
    {
      label: 'URL Length',
      icon: '📏',
      value: features.url_length > 75 ? 'Long' : 'Normal',
      cls:   features.url_length > 75 ? 'warn' : 'ok',
    },
    {
      label: 'Shortened',
      icon: '🔗',
      value: features.is_url_shortened ? 'Yes' : 'No',
      cls:   features.is_url_shortened ? 'warn' : 'ok',
    },
    {
      label: 'Subdomains',
      icon: '🌿',
      value: features.subdomain_count > 2 ? 'Excessive' : 'Normal',
      cls:   features.subdomain_count > 2 ? 'warn' : 'ok',
    },
    {
      label: 'Suspicious TLD',
      icon: '🏷',
      value: features.is_suspicious_tld ? 'Yes' : 'No',
      cls:   features.is_suspicious_tld ? 'danger' : 'ok',
    },
    {
      label: 'Brand Spoof',
      icon: '🎭',
      value: features.brand_in_subdomain ? 'Detected' : 'None',
      cls:   features.brand_in_subdomain ? 'danger' : 'ok',
    },
  ];

  threatGrid.innerHTML = checks.map(c => `
    <div class="threat-cell">
      <div class="threat-cell-icon">${c.icon}</div>
      <div class="threat-cell-label">${c.label}</div>
      <div class="threat-cell-value ${c.cls}">${c.value}</div>
    </div>
  `).join('');
}


// ─── Scan Progress Simulation ──────────────────────────────────────────────
async function simulateStages() {
  const stageList = [
    { el: stages.extract, label: 'Extracting URL features...', durationMs: 400 },
    { el: stages.model,   label: 'Running ML classifier...',  durationMs: 300 },
    { el: stages.shap,    label: 'Computing SHAP values...',  durationMs: 300 },
    { el: stages.score,   label: 'Generating risk score...',  durationMs: 200 },
  ];

  for (let i = 0; i < stageList.length; i++) {
    const { el, durationMs } = stageList[i];
    if (!el) continue;

    // Set previous to done
    if (i > 0 && stageList[i - 1].el) {
      stageList[i - 1].el.className = 'stage-item done';
      stageList[i - 1].el.querySelector('.stage-icon').textContent = '✓';
    }

    el.className = 'stage-item active';
    await sleep(durationMs);
  }

  // Mark last done
  const last = stageList[stageList.length - 1];
  if (last.el) {
    last.el.className = 'stage-item done';
    last.el.querySelector('.stage-icon').textContent = '✓';
  }

  await sleep(100);
}

function resetStages() {
  Object.values(stages).forEach(el => {
    if (!el) return;
    el.className = 'stage-item pending';
    const icon = el.querySelector('.stage-icon');
    if (icon) icon.textContent = el.dataset.icon || '○';
  });
}


// ─── History ───────────────────────────────────────────────────────────────
function addToHistory(data) {
  state.history.unshift({
    url: data.url,
    prediction: data.prediction,
    risk_score: data.risk_score,
    confidence: data.confidence,
    timestamp: data.timestamp,
  });
  state.history = state.history.slice(0, 20);
  localStorage.setItem('pg_history', JSON.stringify(state.history));
}

function renderHistory() {
  if (!state.history.length) return;
  historySection.classList.add('visible');
  historyBody.innerHTML = state.history.map(item => `
    <tr>
      <td class="url-cell mono" title="${escapeHTML(item.url)}">${escapeHTML(truncate(item.url, 60))}</td>
      <td><span class="badge-tiny ${item.prediction}">${item.prediction.toUpperCase()}</span></td>
      <td class="mono">${item.risk_score}/100</td>
      <td class="mono">${item.confidence.toFixed(1)}%</td>
      <td class="mono">${new Date(item.timestamp).toLocaleTimeString()}</td>
      <td>
        <button class="example-chip" data-url="${escapeAttr(item.url)}"
          onclick="document.getElementById('url-input').value=this.dataset.url">
          Re-scan
        </button>
      </td>
    </tr>
  `).join('');
}


// ─── UI Helpers ────────────────────────────────────────────────────────────
function setScanningUI(isScanning) {
  scanBtn.classList.toggle('loading', isScanning);
  urlInput.disabled = isScanning;
}

function showScanProgress() {
  scanProgress.classList.add('visible');
  resetStages();
}

function hideScanProgress() {
  scanProgress.classList.remove('visible');
}

function showError(msg) {
  errorBanner.textContent = `⚠  ${msg}`;
  errorBanner.classList.add('visible');
}

function hideError() {
  errorBanner.classList.remove('visible');
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  const range = to - from;
  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + range * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function truncate(str, maxLen) {
  return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}


// ─── Init ──────────────────────────────────────────────────────────────────
(function init() {
  // Load scan history from localStorage
  if (state.history.length) renderHistory();

  // API health check
  fetch(`${API_BASE}/health`)
    .then(r => r.json())
    .then(data => {
      const dot = document.querySelector('.status-dot');
      const statusText = document.querySelector('.header-status span:last-child');
      if (data.status === 'healthy') {
        if (dot) dot.style.background = data.model_loaded ? 'var(--neon-green)' : 'var(--neon-yellow)';
        if (statusText) statusText.textContent = data.model_loaded
          ? `ONLINE — ${data.model_name.replace('_', ' ').toUpperCase()}`
          : 'ONLINE — RULE-BASED MODE';
      }
    })
    .catch(() => {
      const dot = document.querySelector('.status-dot');
      if (dot) { dot.style.background = 'var(--neon-red)'; dot.style.boxShadow = '0 0 10px var(--neon-red)'; }
    });
})();
