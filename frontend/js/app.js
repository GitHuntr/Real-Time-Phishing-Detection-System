/**
 * PhishGuard — Frontend Application v2
 * Real-Time Phishing Detection Dashboard
 */

'use strict';

// ─── Config ────────────────────────────────────────────────────────────────
const API_BASE = (location.protocol === 'file:')
  ? (window.PHISHGUARD_API_BASE || 'http://localhost:8000')
  : window.location.origin;

// ─── State ─────────────────────────────────────────────────────────────────
const state = {
  scanning: false,
  history:  JSON.parse(localStorage.getItem('pg_history') || '[]'),
  lastResult: null,
  sessionCount: 0,
};

// ─── DOM Helpers ───────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// Core scan elements
const urlInput         = $('url-input');
const scanBtn          = $('scan-btn');
const resultsPanel     = $('results-panel');
const errorBanner      = $('error-banner');
const scanProgress     = $('scan-progress');
const historySection   = $('history-section');
const historyBody      = $('history-body');

// Verdict card
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

// Details panel
const urlDisplay       = $('url-display');
const urlParts         = $('url-parts');
const explanationsList = $('explanations-list');
const featureBars      = $('feature-bars');
const domainToggle     = $('domain-toggle');

// Progress stages
const stages = {
  extract: $('stage-extract'),
  model:   $('stage-model'),
  shap:    $('stage-shap'),
  score:   $('stage-score'),
};


// ═══════════════════════════════════════════════════════════════════════════
// SCROLL PROGRESS BAR
// ═══════════════════════════════════════════════════════════════════════════

(function initScrollProgress() {
  const scrollBar    = $('scroll-bar');
  const mainHeader   = $('main-header');
  if (!scrollBar) return;

  window.addEventListener('scroll', () => {
    const scrollTop  = document.documentElement.scrollTop || document.body.scrollTop;
    const scrollMax  = document.documentElement.scrollHeight - window.innerHeight;
    const pct        = scrollMax > 0 ? (scrollTop / scrollMax) * 100 : 0;
    scrollBar.style.width = `${pct}%`;

    // Sticky header shadow on scroll
    if (mainHeader) {
      mainHeader.classList.toggle('scrolled', scrollTop > 10);
    }
  }, { passive: true });
})();


// ═══════════════════════════════════════════════════════════════════════════
// SCROLL REVEAL — IntersectionObserver
// ═══════════════════════════════════════════════════════════════════════════

(function initScrollReveal() {
  const observer = new IntersectionObserver(
    entries => entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    }),
    { threshold: 0.12 }
  );
  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
})();


// ═══════════════════════════════════════════════════════════════════════════
// TYPEWRITER EFFECT
// ═══════════════════════════════════════════════════════════════════════════

(function initTypewriter() {
  const el = $('typewriter');
  if (!el) return;

  const phrases = [
    'Paste any URL to instantly detect phishing threats.',
    'Powered by XGBoost + SHAP explainability.',
    'Analyze shortened links, IP-based URLs, brand spoofs.',
    'Sub-second inference. Enterprise-grade accuracy.',
    '28+ feature signals. Transparent AI decisions.',
  ];

  let phraseIdx = 0, charIdx = 0, deleting = false;

  function tick() {
    const phrase = phrases[phraseIdx];

    if (!deleting) {
      charIdx++;
      el.textContent = phrase.slice(0, charIdx);
      if (charIdx === phrase.length) {
        deleting = true;
        setTimeout(tick, 2400);
        return;
      }
    } else {
      charIdx--;
      el.textContent = phrase.slice(0, charIdx);
      if (charIdx === 0) {
        deleting = false;
        phraseIdx = (phraseIdx + 1) % phrases.length;
      }
    }
    setTimeout(tick, deleting ? 28 : 48);
  }

  setTimeout(tick, 800);
})();


// ═══════════════════════════════════════════════════════════════════════════
// COUNTER ANIMATIONS (hero stats)
// ═══════════════════════════════════════════════════════════════════════════

(function initCounters() {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      const target = parseInt(el.dataset.target, 10);
      if (isNaN(target)) return;
      animateNumber(el, 0, target, 1600);
      observer.unobserve(el);
    });
  }, { threshold: 0.5 });

  document.querySelectorAll('.counter[data-target]').forEach(el => observer.observe(el));
})();


// ═══════════════════════════════════════════════════════════════════════════
// PARTICLE CANVAS
// ═══════════════════════════════════════════════════════════════════════════

(function initParticles() {
  const canvas = $('particle-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let particles = [];

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  class Particle {
    constructor() { this.reset(); }
    reset() {
      this.x      = Math.random() * canvas.width;
      this.y      = Math.random() * canvas.height;
      this.size   = Math.random() * 1.5 + 0.5;
      this.speedX = (Math.random() - 0.5) * 0.4;
      this.speedY = (Math.random() - 0.5) * 0.4;
      this.opacity = Math.random() * 0.5 + 0.1;
      this.color  = Math.random() > 0.7 ? '#00e5ff' : '#00ff9f';
    }
    update() {
      this.x += this.speedX;
      this.y += this.speedY;
      if (this.x < 0 || this.x > canvas.width || this.y < 0 || this.y > canvas.height) this.reset();
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle  = this.color;
      ctx.globalAlpha = this.opacity;
      ctx.fill();
    }
  }

  function init() { particles = Array.from({ length: 80 }, () => new Particle()); }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.globalAlpha = 1;
    particles.forEach((p1, i) => {
      particles.slice(i + 1).forEach(p2 => {
        const dx = p1.x - p2.x, dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(0, 229, 255, ${0.15 * (1 - dist / 120)})`;
          ctx.lineWidth   = 0.5;
          ctx.stroke();
        }
      });
    });
    particles.forEach(p => { p.update(); p.draw(); });
    ctx.globalAlpha = 1;
    requestAnimationFrame(animate);
  }

  resize();
  init();
  animate();
  window.addEventListener('resize', () => { resize(); init(); }, { passive: true });
})();


// ═══════════════════════════════════════════════════════════════════════════
// TOAST NOTIFICATION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

function showToast(message, type = 'info', duration = 4000) {
  const container = $('toast-container');
  if (!container) return;

  const icons = { success: '✓', error: '✕', warn: '⚠', info: 'ℹ' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || icons.info}</span>
    <span class="toast-msg">${escapeHTML(message)}</span>
  `;

  const dismiss = () => {
    toast.classList.add('toast-exit');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
  };

  toast.addEventListener('click', dismiss);
  container.appendChild(toast);
  setTimeout(dismiss, duration);
}


// ═══════════════════════════════════════════════════════════════════════════
// SESSION COUNTER
// ═══════════════════════════════════════════════════════════════════════════

function incrementSessionCount() {
  state.sessionCount++;
  const el = $('session-count');
  if (!el) return;
  el.textContent = state.sessionCount;
  el.classList.remove('session-count-bump');
  void el.offsetWidth; // force reflow
  el.classList.add('session-count-bump');
}


// ═══════════════════════════════════════════════════════════════════════════
// KEYBOARD SHORTCUTS MODAL
// ═══════════════════════════════════════════════════════════════════════════

(function initModal() {
  const modal     = $('kbd-modal');
  const openBtn   = $('kbd-hints-btn');
  const closeBtn  = $('kbd-modal-close');
  if (!modal) return;

  const open  = () => modal.classList.remove('hidden');
  const close = () => modal.classList.add('hidden');

  if (openBtn)  openBtn.addEventListener('click', open);
  if (closeBtn) closeBtn.addEventListener('click', close);

  // Close on overlay click
  modal.addEventListener('click', e => { if (e.target === modal) close(); });
})();


// ═══════════════════════════════════════════════════════════════════════════
// KEYBOARD SHORTCUTS
// ═══════════════════════════════════════════════════════════════════════════

document.addEventListener('keydown', e => {
  const tag = document.activeElement.tagName;
  const typing = tag === 'INPUT' || tag === 'TEXTAREA';

  // `/` → focus URL input
  if (e.key === '/' && !typing) {
    e.preventDefault();
    if (urlInput && document.getElementById('mode-single') &&
        !document.getElementById('mode-single').classList.contains('hidden')) {
      urlInput.focus();
      urlInput.select();
    }
  }

  // Esc → clear/close
  if (e.key === 'Escape') {
    const modal = $('kbd-modal');
    if (modal && !modal.classList.contains('hidden')) {
      modal.classList.add('hidden');
      return;
    }
    if (urlInput) { urlInput.value = ''; urlInput.focus(); toggleClearBtn(); }
  }

  // Ctrl+E → export last result
  if (e.ctrlKey && e.key === 'e') {
    e.preventDefault();
    exportResult();
  }

  // Ctrl+/ → open shortcuts modal
  if (e.ctrlKey && e.key === '/') {
    e.preventDefault();
    const modal = $('kbd-modal');
    if (modal) modal.classList.toggle('hidden');
  }
});


// ═══════════════════════════════════════════════════════════════════════════
// SCAN MODE TABS (Single / Batch / Upload)
// ═══════════════════════════════════════════════════════════════════════════

(function initScanTabs() {
  const tabs       = document.querySelectorAll('.mode-tab');
  const modeSingle = $('mode-single');
  const modeBatch  = $('mode-batch');
  const modeUpload = $('mode-upload');
  const optsRow    = $('scan-options-row');
  if (!tabs.length) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const mode = tab.dataset.mode;
      if (modeSingle) modeSingle.classList.toggle('hidden', mode !== 'single');
      if (modeBatch)  modeBatch.classList.toggle('hidden',  mode !== 'batch');
      if (modeUpload) modeUpload.classList.toggle('hidden', mode !== 'upload');
      if (optsRow)    optsRow.classList.toggle('upload-mode', mode === 'upload');
    });
  });
})();


// ═══════════════════════════════════════════════════════════════════════════
// INPUT CLEAR BUTTON
// ═══════════════════════════════════════════════════════════════════════════

function toggleClearBtn() {
  const clearBtn = $('clear-input-btn');
  if (!clearBtn || !urlInput) return;
  clearBtn.style.display = urlInput.value.length ? 'flex' : 'none';
}

if (urlInput) {
  urlInput.addEventListener('input', toggleClearBtn);
}

const clearInputBtn = $('clear-input-btn');
if (clearInputBtn) {
  clearInputBtn.addEventListener('click', () => {
    if (urlInput) { urlInput.value = ''; urlInput.focus(); }
    toggleClearBtn();
  });
}


// ═══════════════════════════════════════════════════════════════════════════
// EXAMPLE URL CHIPS
// ═══════════════════════════════════════════════════════════════════════════

document.querySelectorAll('.example-chip').forEach(chip => {
  if (!chip.dataset.url) return; // skip history re-scan chips
  chip.addEventListener('click', () => {
    if (!urlInput) return;
    urlInput.value = chip.dataset.url;
    urlInput.focus();
    toggleClearBtn();
    // Switch to single mode if not active
    const singleTab = $('tab-single');
    if (singleTab) singleTab.click();
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// SINGLE-URL SCAN FLOW
// ═══════════════════════════════════════════════════════════════════════════

if (scanBtn)  scanBtn.addEventListener('click', startScan);
if (urlInput) urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

async function startScan() {
  const url = urlInput ? urlInput.value.trim() : '';
  if (!url || state.scanning) return;

  hideError();
  state.scanning = true;
  setScanningUI(true);
  showScanProgress();

  try {
    await simulateStages();
    const includeDomain = domainToggle && domainToggle.checked;
    const data = await fetchPrediction(url, includeDomain);

    state.lastResult = data;
    renderResults(data);
    addToHistory(data);
    renderHistory();
    incrementSessionCount();

    const levelLabel = (data.risk_level || 'unknown').toUpperCase();
    showToast(`Analysis complete — ${levelLabel}`, data.risk_level === 'legitimate' ? 'success' : 'warn');
  } catch (err) {
    showError(err.message || 'Failed to analyze URL. Ensure the API server is running.');
    showToast(err.message || 'Scan failed', 'error');
  } finally {
    state.scanning = false;
    setScanningUI(false);
    hideScanProgress();
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// BATCH SCAN FLOW
// ═══════════════════════════════════════════════════════════════════════════

const batchScanBtn = $('batch-scan-btn');
if (batchScanBtn) {
  batchScanBtn.addEventListener('click', startBatchScan);
}

async function startBatchScan() {
  const textarea = $('batch-input');
  const container = $('batch-results');
  if (!textarea || !container) return;

  const rawLines = textarea.value.split('\n').map(l => l.trim()).filter(Boolean);
  const urls = [...new Set(rawLines)].slice(0, 10);

  if (!urls.length) {
    showToast('Enter at least one URL', 'warn');
    return;
  }

  batchScanBtn.classList.add('loading');
  batchScanBtn.disabled = true;
  container.classList.remove('hidden');
  container.innerHTML = `<div style="color:var(--text-muted);font-size:13px;padding:8px 0;">Scanning ${urls.length} URL${urls.length > 1 ? 's' : ''}…</div>`;

  try {
    const resp = await fetch(`${API_BASE}/predict/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls }),
      signal: abortTimeout(60000),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }

    const data = await resp.json();
    renderBatchResults(container, data.results || []);
    incrementSessionCount();
    showToast(`Batch scan complete — ${data.count} URLs`, 'success');
  } catch (err) {
    container.innerHTML = `<div style="color:var(--neon-red);font-size:13px;padding:8px 0;">Error: ${escapeHTML(err.message)}</div>`;
    showToast(err.message || 'Batch scan failed', 'error');
  } finally {
    batchScanBtn.classList.remove('loading');
    batchScanBtn.disabled = false;
  }
}

function renderBatchResults(container, results) {
  if (!results.length) {
    container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No results.</div>';
    return;
  }

  const verdictLabels = { phishing: '⚠ PHISHING', suspicious: '⚡ SUSPICIOUS', legitimate: '✓ SAFE', error: '— ERROR' };

  container.innerHTML = results.map((r, i) => `
    <div class="batch-result-row ${r.prediction || 'error-row'}" style="animation-delay:${i * 40}ms">
      <div class="mono" style="font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeAttr(r.url)}">${escapeHTML(truncate(r.url, 60))}</div>
      <div><span class="badge-tiny ${r.prediction || 'error'}">${verdictLabels[r.prediction] || (r.prediction || 'error').toUpperCase()}</span></div>
      <div class="mono" style="font-size:12px;">${r.risk_score >= 0 ? r.risk_score + '/100' : '—'}</div>
      <div class="mono" style="font-size:12px;">${r.confidence ? r.confidence.toFixed(1) + '%' : '—'}</div>
    </div>
  `).join('');
}


// ═══════════════════════════════════════════════════════════════════════════
// API CALL
// ═══════════════════════════════════════════════════════════════════════════

async function fetchPrediction(url, includeDomain = false) {
  const resp = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, include_domain_features: includeDomain }),
    signal: abortTimeout(30000),
  });

  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data.detail || `HTTP ${resp.status}`);
  }

  return resp.json();
}


// ═══════════════════════════════════════════════════════════════════════════
// RENDER RESULTS
// ═══════════════════════════════════════════════════════════════════════════

function renderResults(data) {
  const level = data.risk_level || data.prediction;

  setVerdictClass(level);
  renderGauge(data.risk_score, level);
  renderVerdict(level);
  renderConfidence(data.confidence, level);
  renderMeta(data);
  renderURLParts(data.normalized_url || data.url);
  renderExplanations(data.explanations, level);
  renderFeatureBars(data.top_features || []);
  renderThreatGrid(data.features || {});

  resultsPanel.classList.add('visible');
  setTimeout(() => resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);
}

function setVerdictClass(level) {
  verdictCard.className = `verdict-card ${level}`;
}

function renderGauge(score, level) {
  const circumference = 2 * Math.PI * 80;
  const offset        = circumference * (1 - Math.min(score, 100) / 100);
  const colorMap      = { phishing: '#ff2d55', suspicious: '#ffcc00', legitimate: '#00ff9f' };

  gaugeFill.style.stroke = colorMap[level] || '#00e5ff';
  gaugeFill.setAttribute('stroke-dasharray', circumference.toFixed(1));

  setTimeout(() => { gaugeFill.style.strokeDashoffset = offset.toFixed(1); }, 100);
  animateNumber(riskScoreNum, 0, score, 1200);
  riskScoreNum.style.color = colorMap[level] || '#00e5ff';
}

function renderVerdict(level) {
  const cfg = {
    phishing:  { icon: '⚠', text: 'Phishing' },
    suspicious: { icon: '⚡', text: 'Suspicious' },
    legitimate: { icon: '✓', text: 'Safe' },
  };
  const c = cfg[level] || cfg.legitimate;
  verdictBadge.className = `verdict-badge ${level}`;
  verdictIcon.textContent = c.icon;
  verdictText.textContent = c.text;
}

function renderConfidence(conf, level) {
  confidenceVal.textContent = `${conf.toFixed(1)}%`;
  confidenceBar.className   = `bar-fill ${level}`;
  setTimeout(() => { confidenceBar.style.width = `${Math.min(conf, 100)}%`; }, 150);
}

function renderMeta(data) {
  if (modelUsed)    modelUsed.textContent    = data.model_used || '—';
  if (latencyVal)   latencyVal.textContent   = `${data.latency_ms}ms`;
  if (timestampVal) timestampVal.textContent = new Date(data.timestamp).toLocaleTimeString();
}

function renderURLParts(url) {
  if (urlDisplay) urlDisplay.textContent = url;
  if (!urlParts) return;
  try {
    const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    urlParts.innerHTML = [
      url.startsWith('https')
        ? `<span class="url-part scheme">HTTPS 🔒</span>`
        : `<span class="url-part scheme" style="color:var(--neon-red)">HTTP ⚠</span>`,
      `<span class="url-part domain">${escapeHTML(parsed.hostname)}</span>`,
      parsed.pathname !== '/' ? `<span class="url-part path">${escapeHTML(parsed.pathname)}</span>` : '',
      parsed.search    ? `<span class="url-part query">${escapeHTML(parsed.search)}</span>` : '',
    ].filter(Boolean).join('');
  } catch {
    urlParts.innerHTML = `<span class="url-part domain">${escapeHTML(url)}</span>`;
  }
}

function renderExplanations(explanations, level) {
  if (!explanationsList) return;
  explanationsList.innerHTML = '';

  if (!explanations || !explanations.length) {
    explanationsList.innerHTML = `<div class="explanation-item safe">
      <span class="exp-icon">✓</span>
      <span>No significant phishing indicators detected.</span>
    </div>`;
    return;
  }

  explanations.forEach((exp, i) => {
    const cls  = level === 'phishing' ? 'risk' : level === 'suspicious' ? 'warn' : 'safe';
    const icon = level === 'phishing' ? '⚠' : level === 'suspicious' ? '●' : '✓';
    const el   = document.createElement('div');
    el.className = `explanation-item ${cls}`;
    el.style.animationDelay = `${i * 60}ms`;
    el.innerHTML = `<span class="exp-icon">${icon}</span><span>${escapeHTML(exp)}</span>`;
    explanationsList.appendChild(el);
  });
}

function renderFeatureBars(topFeatures) {
  if (!featureBars) return;
  featureBars.innerHTML = '';

  if (!topFeatures || !topFeatures.length) {
    featureBars.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No feature details available.</div>';
    return;
  }

  const maxShap = Math.max(...topFeatures.map(f => f.shap_value || 0), 1);

  topFeatures.forEach(feat => {
    const pct = ((feat.shap_value || 0) / maxShap * 100).toFixed(1);
    const dir = feat.direction || 'phishing';
    const el  = document.createElement('div');
    el.className = 'feature-bar-item';
    el.innerHTML = `
      <div class="feature-bar-label" title="${escapeAttr(feat.label || feat.name)}">${escapeHTML(feat.label || feat.name)}</div>
      <div class="feature-bar-track">
        <div class="feature-bar-fill ${dir}" data-pct="${pct}"></div>
      </div>
      <div class="feature-bar-value">${pct}%</div>
    `;
    featureBars.appendChild(el);
  });

  setTimeout(() => {
    document.querySelectorAll('.feature-bar-fill').forEach(el => {
      el.style.width = el.dataset.pct + '%';
    });
  }, 200);
}

function renderThreatGrid(features) {
  const grid = $('threat-grid');
  if (!grid) return;

  const checks = [
    { label: 'HTTPS',         icon: features.has_https        ? '🔒' : '🔓', value: features.has_https        ? 'Secure'    : 'Insecure',  cls: features.has_https        ? 'ok'     : 'danger' },
    { label: 'IP in URL',     icon: '🌐',                                      value: features.has_ip_address   ? 'Yes'       : 'No',        cls: features.has_ip_address   ? 'danger' : 'ok'    },
    { label: '@ Symbol',      icon: '📧',                                      value: features.has_at_symbol    ? 'Found'     : 'Clean',     cls: features.has_at_symbol    ? 'danger' : 'ok'    },
    { label: 'URL Length',    icon: '📏',                                      value: features.url_length > 75  ? 'Long'      : 'Normal',    cls: features.url_length > 75  ? 'warn'   : 'ok'    },
    { label: 'Shortened',     icon: '🔗',                                      value: features.is_url_shortened ? 'Yes'       : 'No',        cls: features.is_url_shortened ? 'warn'   : 'ok'    },
    { label: 'Subdomains',    icon: '🌿',                                      value: features.subdomain_count > 2 ? 'Excessive' : 'Normal', cls: features.subdomain_count > 2 ? 'warn' : 'ok'   },
    { label: 'Susp. TLD',     icon: '🏷',                                      value: features.is_suspicious_tld ? 'Yes'      : 'No',        cls: features.is_suspicious_tld ? 'danger': 'ok'   },
    { label: 'Brand Spoof',   icon: '🎭',                                      value: features.brand_in_subdomain ? 'Detected': 'None',      cls: features.brand_in_subdomain? 'danger': 'ok'   },
  ];

  grid.innerHTML = checks.map(c => `
    <div class="threat-cell">
      <div class="threat-cell-icon">${c.icon}</div>
      <div class="threat-cell-label">${c.label}</div>
      <div class="threat-cell-value ${c.cls}">${c.value}</div>
    </div>
  `).join('');
}


// ═══════════════════════════════════════════════════════════════════════════
// EXPORT & COPY
// ═══════════════════════════════════════════════════════════════════════════

function exportResult() {
  if (!state.lastResult) {
    showToast('Run a scan first', 'warn');
    return;
  }
  try {
    const blob = new Blob([JSON.stringify(state.lastResult, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `phishguard_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Report exported as JSON', 'success');
  } catch {
    showToast('Export failed', 'error');
  }
}

const exportBtn = $('export-btn');
if (exportBtn) exportBtn.addEventListener('click', exportResult);

const copyResultBtn = $('copy-result-btn');
if (copyResultBtn) {
  copyResultBtn.addEventListener('click', () => {
    if (!state.lastResult) { showToast('Run a scan first', 'warn'); return; }
    const r   = state.lastResult;
    const txt = `PhishGuard Analysis\nURL: ${r.url}\nVerdict: ${r.risk_level.toUpperCase()}\nRisk Score: ${r.risk_score}/100\nConfidence: ${r.confidence}%\nModel: ${r.model_used}\nTimestamp: ${r.timestamp}\n\nTop signals:\n${(r.explanations || []).join('\n')}`;
    navigator.clipboard.writeText(txt)
      .then(() => showToast('Result copied to clipboard', 'success'))
      .catch(() => showToast('Clipboard access denied', 'error'));
  });
}

const copyUrlBtn = $('copy-url-btn');
if (copyUrlBtn) {
  copyUrlBtn.addEventListener('click', () => {
    if (!state.lastResult) { showToast('No URL to copy', 'warn'); return; }
    navigator.clipboard.writeText(state.lastResult.normalized_url || state.lastResult.url)
      .then(() => showToast('URL copied to clipboard', 'success'))
      .catch(() => showToast('Clipboard access denied', 'error'));
  });
}


// ═══════════════════════════════════════════════════════════════════════════
// SCAN PROGRESS SIMULATION
// ═══════════════════════════════════════════════════════════════════════════

async function simulateStages() {
  const stageList = [
    { el: stages.extract, durationMs: 400 },
    { el: stages.model,   durationMs: 300 },
    { el: stages.shap,    durationMs: 300 },
    { el: stages.score,   durationMs: 200 },
  ];

  for (let i = 0; i < stageList.length; i++) {
    const { el, durationMs } = stageList[i];
    if (!el) continue;
    if (i > 0 && stageList[i - 1].el) {
      stageList[i - 1].el.className = 'stage-item done';
      const icon = stageList[i - 1].el.querySelector('.stage-icon');
      if (icon) icon.textContent = '✓';
    }
    el.className = 'stage-item active';
    await sleep(durationMs);
  }

  const last = stageList[stageList.length - 1];
  if (last.el) {
    last.el.className = 'stage-item done';
    const icon = last.el.querySelector('.stage-icon');
    if (icon) icon.textContent = '✓';
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


// ═══════════════════════════════════════════════════════════════════════════
// SCAN HISTORY
// ═══════════════════════════════════════════════════════════════════════════

function addToHistory(data) {
  state.history.unshift({
    url:        data.url,
    prediction: data.prediction,
    risk_score: data.risk_score,
    confidence: data.confidence,
    timestamp:  data.timestamp,
  });
  state.history = state.history.slice(0, 20);
  localStorage.setItem('pg_history', JSON.stringify(state.history));
}

function clearHistory() {
  state.history = [];
  localStorage.removeItem('pg_history');
  if (historyBody)   historyBody.innerHTML = '';
  if (historySection) historySection.classList.remove('visible');
  showToast('Scan history cleared', 'info');
}

function renderHistory() {
  if (!state.history.length) return;
  if (historySection) historySection.classList.add('visible');
  if (!historyBody) return;

  historyBody.innerHTML = state.history.map(item => `
    <tr>
      <td class="url-cell mono" title="${escapeAttr(item.url)}">${escapeHTML(truncate(item.url, 60))}</td>
      <td><span class="badge-tiny ${item.prediction}">${item.prediction.toUpperCase()}</span></td>
      <td class="mono">${item.risk_score}/100</td>
      <td class="mono">${item.confidence.toFixed(1)}%</td>
      <td class="mono">${new Date(item.timestamp).toLocaleTimeString()}</td>
      <td>
        <button class="example-chip rescan-btn" data-url="${escapeAttr(item.url)}">Re-scan</button>
      </td>
    </tr>
  `).join('');

  // Re-scan buttons
  historyBody.querySelectorAll('.rescan-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (!urlInput) return;
      urlInput.value = btn.dataset.url;
      toggleClearBtn();
      const singleTab = $('tab-single');
      if (singleTab) singleTab.click();
      urlInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      urlInput.focus();
    });
  });
}

// Clear history buttons
const clearHistoryBtn    = $('clear-history-btn');
const footerClearBtn     = $('footer-clear-history');
if (clearHistoryBtn) clearHistoryBtn.addEventListener('click', clearHistory);
if (footerClearBtn)  footerClearBtn.addEventListener('click', e => { e.preventDefault(); clearHistory(); });


// ═══════════════════════════════════════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function setScanningUI(isScanning) {
  if (scanBtn)   scanBtn.classList.toggle('loading', isScanning);
  if (urlInput)  urlInput.disabled = isScanning;
}

function showScanProgress() {
  if (scanProgress) { scanProgress.classList.add('visible'); resetStages(); }
}

function hideScanProgress() {
  if (scanProgress) scanProgress.classList.remove('visible');
}

function showError(msg) {
  if (!errorBanner) return;
  errorBanner.innerHTML = `<span>⚠</span> <span>${escapeHTML(msg)}</span>`;
  errorBanner.classList.add('visible');
}

function hideError() {
  if (errorBanner) errorBanner.classList.remove('visible');
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  (function step(now) {
    const t = Math.min((now - start) / duration, 1);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  })(start);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function abortTimeout(ms) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return AbortSignal.timeout(ms);
  }
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), ms);
  return ctrl.signal;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) + '…' : str;
}


// ═══════════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════════

(function init() {
  // Render stored history
  if (state.history.length) renderHistory();

  // API health check
  fetch(`${API_BASE}/health`)
    .then(r => r.json())
    .then(data => {
      const dot        = document.querySelector('.status-dot');
      const statusText = $('status-text');
      if (data.status === 'healthy') {
        if (dot) {
          dot.style.background  = data.model_loaded ? 'var(--neon-green)' : 'var(--neon-yellow)';
          dot.style.boxShadow   = data.model_loaded ? '0 0 10px var(--neon-green)' : '0 0 10px var(--neon-yellow)';
        }
        if (statusText) statusText.textContent = data.model_loaded
          ? `ONLINE — ${(data.model_name || '').replace(/_/g, ' ').toUpperCase()}`
          : 'ONLINE — RULE-BASED';
        showToast(
          data.model_loaded ? `Model ready: ${data.model_name}` : 'Running in rule-based mode',
          data.model_loaded ? 'success' : 'warn',
          3000
        );
      } else {
        if (dot) { dot.style.background = 'var(--neon-red)'; dot.style.boxShadow = '0 0 10px var(--neon-red)'; }
        if (statusText) statusText.textContent = 'DEGRADED';
      }
    })
    .catch(() => {
      const dot = document.querySelector('.status-dot');
      if (dot) { dot.style.background = 'var(--neon-red)'; dot.style.boxShadow = '0 0 10px var(--neon-red)'; }
      const statusText = $('status-text');
      if (statusText) statusText.textContent = 'OFFLINE';
      showToast('API server unreachable — start the backend', 'error', 6000);
    });
})();


// ═══════════════════════════════════════════════════════════════════════════
// PARALLAX — hero moves at a slower rate on scroll
// ═══════════════════════════════════════════════════════════════════════════

(function initParallax() {
  const parallaxEls = document.querySelectorAll('[data-parallax]');
  if (!parallaxEls.length) return;

  window.addEventListener('scroll', () => {
    const scrollY = window.scrollY;
    parallaxEls.forEach(el => {
      // Wait for reveal animation to complete before applying parallax
      if (el.classList.contains('reveal') && !el.classList.contains('visible')) return;
      const factor = parseFloat(el.dataset.parallax) || 0.2;
      el.style.transform = `translateY(${scrollY * factor}px)`;
    });
  }, { passive: true });
})();


// ═══════════════════════════════════════════════════════════════════════════
// 3D TILT CARDS
// ═══════════════════════════════════════════════════════════════════════════

(function initTiltCards() {
  const isMobile = () => window.matchMedia('(max-width: 700px)').matches;

  function onMove(e) {
    if (isMobile()) return;
    const card   = e.currentTarget;
    const rect   = card.getBoundingClientRect();
    const cx     = rect.left + rect.width  / 2;
    const cy     = rect.top  + rect.height / 2;
    const dx     = (e.clientX - cx) / (rect.width  / 2);
    const dy     = (e.clientY - cy) / (rect.height / 2);
    const rotX   = -dy * 6;
    const rotY   =  dx * 6;
    card.style.transform = `perspective(800px) rotateX(${rotX}deg) rotateY(${rotY}deg) scale(1.015)`;
  }

  function onLeave(e) {
    e.currentTarget.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg) scale(1)';
  }

  document.querySelectorAll('.tilt-card').forEach(card => {
    card.addEventListener('mousemove', onMove, { passive: true });
    card.addEventListener('mouseleave', onLeave, { passive: true });
  });
})();


// ═══════════════════════════════════════════════════════════════════════════
// RIPPLE EFFECT on .ripple-btn buttons
// ═══════════════════════════════════════════════════════════════════════════

(function initRipple() {
  document.addEventListener('click', e => {
    const btn = e.target.closest('.ripple-btn');
    if (!btn) return;

    const rect    = btn.getBoundingClientRect();
    const x       = e.clientX - rect.left;
    const y       = e.clientY - rect.top;
    const size    = Math.max(rect.width, rect.height) * 1.5;
    const wave    = document.createElement('span');
    wave.className = 'ripple-wave';
    wave.style.cssText = `
      width: ${size}px; height: ${size}px;
      left: ${x - size / 2}px; top: ${y - size / 2}px;
    `;
    btn.appendChild(wave);
    wave.addEventListener('animationend', () => wave.remove(), { once: true });
  });
})();


// ═══════════════════════════════════════════════════════════════════════════
// FILE UPLOAD FEATURE
// ═══════════════════════════════════════════════════════════════════════════

(function initFileUpload() {
  const zone         = $('upload-zone');
  const fileInput    = $('upload-file-input');
  const fileInfo     = $('upload-file-info');
  const filenameEl   = $('upload-filename');
  const filesizeEl   = $('upload-filesize');
  const clearBtn     = $('upload-clear-btn');
  const scanBtn      = $('upload-scan-btn');
  const progressWrap = $('upload-progress-wrap');
  const progressBar  = $('upload-progress-bar');
  const progressLbl  = $('upload-progress-label');
  const progressPct  = $('upload-progress-pct');
  const summaryEl    = $('upload-summary');
  const resultsEl    = $('upload-results');
  const tbodyEl      = $('upload-tbody');
  const countEl      = $('upload-results-count');
  const exportBtn    = $('upload-export-btn');

  let uploadedFile   = null;
  let lastUploadData = null;

  if (!zone) return;

  // ── Open file picker ───────────────────────────────────────────────────
  zone.addEventListener('click', e => {
    if (e.target === fileInput) return;
    fileInput && fileInput.click();
  });
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput && fileInput.click(); } });

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files[0]) setFile(fileInput.files[0]);
    });
  }

  // ── Drag and drop ──────────────────────────────────────────────────────
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', e => { if (!zone.contains(e.relatedTarget)) zone.classList.remove('drag-over'); });
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) setFile(file);
  });

  // ── Clear file ─────────────────────────────────────────────────────────
  if (clearBtn) {
    clearBtn.addEventListener('click', e => {
      e.stopPropagation();
      resetUpload();
    });
  }

  // ── Scan button ────────────────────────────────────────────────────────
  if (scanBtn) {
    scanBtn.addEventListener('click', startUploadScan);
  }

  // ── Export CSV ─────────────────────────────────────────────────────────
  if (exportBtn) {
    exportBtn.addEventListener('click', exportUploadCSV);
  }

  // ── Set file ────────────────────────────────────────────────────────────
  function setFile(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['txt', 'csv'].includes(ext)) {
      showToast('Only .txt and .csv files are supported', 'error');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      showToast('File exceeds 5 MB limit', 'error');
      return;
    }

    uploadedFile = file;

    // Show file info
    if (zone)      zone.classList.add('hidden');
    if (fileInfo)  fileInfo.classList.remove('hidden');
    if (filenameEl) filenameEl.textContent = file.name;
    if (filesizeEl) filesizeEl.textContent = formatFileSize(file.size);
    if (scanBtn)    scanBtn.classList.remove('hidden');

    // Reset results
    hideUploadResults();
  }

  // ── Reset ────────────────────────────────────────────────────────────────
  function resetUpload() {
    uploadedFile = null;
    if (fileInput) fileInput.value = '';
    if (zone)      zone.classList.remove('hidden');
    if (fileInfo)  fileInfo.classList.add('hidden');
    if (scanBtn)   scanBtn.classList.add('hidden');
    hideUploadResults();
  }

  function hideUploadResults() {
    if (progressWrap) progressWrap.classList.add('hidden');
    if (summaryEl)    summaryEl.classList.add('hidden');
    if (resultsEl)    resultsEl.classList.add('hidden');
    if (progressBar)  progressBar.style.width = '0%';
  }

  // ── Start scan ───────────────────────────────────────────────────────────
  async function startUploadScan() {
    if (!uploadedFile) return;

    scanBtn.disabled = true;
    scanBtn.classList.add('loading');

    if (progressWrap) progressWrap.classList.remove('hidden');
    if (summaryEl)    summaryEl.classList.add('hidden');
    if (resultsEl)    resultsEl.classList.add('hidden');
    setUploadProgress(0, 'Uploading file…');

    const formData = new FormData();
    formData.append('file', uploadedFile);

    try {
      let fakePct = 0;
      const progressTick = setInterval(() => {
        fakePct = Math.min(fakePct + 3, 60);
        setUploadProgress(fakePct, 'Scanning URLs…');
      }, 150);

      const resp = await fetch(`${API_BASE}/predict/upload`, {
        method: 'POST',
        body:   formData,
        signal: abortTimeout(120000),
      });

      clearInterval(progressTick);

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${resp.status}`);
      }

      const data = await resp.json();
      lastUploadData = data;

      setUploadProgress(100, 'Complete');
      await sleep(300);
      renderUploadResults(data);
      showToast(
        `Scan complete — ${data.threat_count} threat${data.threat_count !== 1 ? 's' : ''} in ${data.total} URLs`,
        data.threat_count > 0 ? 'warn' : 'success'
      );
    } catch (err) {
      if (progressWrap) progressWrap.classList.add('hidden');
      showToast(err.message || 'Upload scan failed', 'error');
    } finally {
      scanBtn.disabled = false;
      scanBtn.classList.remove('loading');
    }
  }

  // ── Render results ───────────────────────────────────────────────────────
  function renderUploadResults(data) {
    const stats = data.stats || {};
    const byId  = id => document.getElementById(id);
    if (byId('us-total'))     animateNumber(byId('us-total'),     0, data.total,              800);
    if (byId('us-phishing'))  animateNumber(byId('us-phishing'),  0, stats.phishing  || 0,    800);
    if (byId('us-suspicious'))animateNumber(byId('us-suspicious'),0, stats.suspicious || 0,   800);
    if (byId('us-safe'))      animateNumber(byId('us-safe'),      0, stats.legitimate || 0,   800);
    if (summaryEl) summaryEl.classList.remove('hidden');

    if (!tbodyEl) return;
    const verdictLabels = {
      phishing:  '⚠ PHISHING',
      suspicious:'⚡ SUSPICIOUS',
      legitimate:'✓ SAFE',
      error:     '— ERROR',
    };
    tbodyEl.innerHTML = (data.results || []).map((r, i) => `
      <tr class="row-${r.prediction || 'error'}">
        <td class="mono" style="color:var(--text-muted);font-size:11px;">${i + 1}</td>
        <td class="url-col" title="${escapeAttr(r.url)}">${escapeHTML(truncate(r.url, 65))}</td>
        <td><span class="badge-tiny ${r.prediction || ''}">${verdictLabels[r.prediction] || (r.prediction || 'error').toUpperCase()}</span></td>
        <td class="mono" style="font-size:12px;">${r.risk_score >= 0 ? r.risk_score + '/100' : '—'}</td>
        <td class="mono" style="font-size:12px;">${r.confidence ? r.confidence.toFixed(1) + '%' : '—'}</td>
      </tr>
    `).join('');

    if (countEl)  countEl.textContent = `${data.total} URLs scanned — ${data.threat_count} threats detected`;
    if (resultsEl) resultsEl.classList.remove('hidden');
  }

  // ── Export CSV ────────────────────────────────────────────────────────────
  function exportUploadCSV() {
    if (!lastUploadData) return;
    const rows = [['#', 'URL', 'Verdict', 'Risk Score', 'Confidence']];
    (lastUploadData.results || []).forEach((r, i) => {
      rows.push([
        i + 1, r.url,
        r.risk_level || r.prediction,
        r.risk_score,
        r.confidence ? r.confidence.toFixed(1) + '%' : '',
      ]);
    });
    const csv  = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `phishguard_upload_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Exported as CSV', 'success');
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function setUploadProgress(pct, label) {
    if (progressBar) progressBar.style.width = `${pct}%`;
    if (progressPct) progressPct.textContent  = `${Math.round(pct)}%`;
    if (progressLbl) progressLbl.textContent  = label || '';
  }

  function formatFileSize(bytes) {
    if (bytes < 1024)        return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
})();

