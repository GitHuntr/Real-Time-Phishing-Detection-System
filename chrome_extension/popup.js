"use strict";

const API_BASE = "http://localhost:8000";
const DASHBOARD_URL = "http://localhost:8000/static/index.html";

const $ = id => document.getElementById(id);

document.addEventListener("DOMContentLoaded", async () => {
  checkAPIHealth();
  loadCurrentTab();
  $("scan-btn").addEventListener("click", scanCurrentTab);
  $("open-dashboard").href = DASHBOARD_URL;
  $("open-dashboard").addEventListener("click", e => {
    e.preventDefault();
    chrome.tabs.create({ url: DASHBOARD_URL });
  });
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    chrome.storage.session.get(["result_" + tab.id], data => {
      const result = data["result_" + tab.id];
      if (result) renderResult(result);
    });
  }
});

async function checkAPIHealth() {
  try {
    const res = await fetch(API_BASE + "/health", { signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    if (data.status === "healthy") {
      $("api-dot").style.background = "#00ff9f";
      $("api-dot").style.boxShadow = "0 0 8px #00ff9f";
      $("api-status").textContent = data.model_loaded ? "ML ONLINE" : "RULE-BASED";
    }
  } catch {
    $("api-dot").style.background = "#ff2d55";
    $("api-dot").style.boxShadow = "0 0 8px #ff2d55";
    $("api-status").textContent = "OFFLINE";
    showError("API server not running. Start backend first.");
  }
}

async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url) {
    const display = tab.url.length > 52 ? tab.url.slice(0, 52) + "..." : tab.url;
    $("current-url").textContent = display;
    $("current-url").title = tab.url;
  }
}

async function scanCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("about:")) {
    showError("Cannot scan browser internal pages.");
    return;
  }
  hideError();
  setScanningState(true);
  try {
    const response = await fetch(API_BASE + "/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url, include_domain_features: false }),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || "HTTP " + response.status);
    }
    const data = await response.json();
    renderResult(data);
    chrome.storage.session.set({ ["result_" + tab.id]: data });
    if (data.risk_level === "phishing" && data.risk_score >= 70) {
      chrome.runtime.sendMessage({
        type: "PHISHING_DETECTED",
        url: tab.url,
        score: data.risk_score,
        tabId: tab.id,
      });
    }
  } catch (err) {
    showError(err.message || "Scan failed. Check if API server is running.");
  } finally {
    setScanningState(false);
  }
}

function renderResult(data) {
  $("idle-state").style.display = "none";
  const level = data.risk_level || data.prediction;
  const card = $("result-card");
  card.className = "result-card " + level;
  const icons = { phishing: "! ", suspicious: "~ ", legitimate: "OK " };
  $("verdict-chip").textContent = (icons[level] || "") + level.toUpperCase();
  $("verdict-chip").className = "verdict-chip " + level;
  animateNumber($("risk-num"), 0, data.risk_score, 900);
  $("risk-num").className = "risk-num " + level;
  setTimeout(() => {
    const w = Math.min(data.confidence, 100);
    $("conf-fill").style.width = w + "%";
  }, 100);
  $("conf-fill").className = "conf-fill " + level;
  $("conf-pct").textContent = data.confidence.toFixed(1) + "%";
  const expList = $("exp-list");
  expList.innerHTML = "";
  const exps = (data.explanations || []).slice(0, 3);
  if (exps.length === 0) {
    expList.innerHTML = "<div class='exp-item " + level + "'>No significant indicators.</div>";
  } else {
    exps.forEach(exp => {
      const el = document.createElement("div");
      el.className = "exp-item " + level;
      el.textContent = exp;
      expList.appendChild(el);
    });
  }
}

function setScanningState(loading) {
  const btn = $("scan-btn");
  btn.classList.toggle("loading", loading);
  btn.disabled = loading;
}

function showError(msg) {
  const el = $("error-msg");
  el.textContent = msg;
  el.classList.add("visible");
}

function hideError() { $("error-msg").classList.remove("visible"); }

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  const range = to - from;
  function step(now) {
    const p = Math.min((now - start) / duration, 1);
    const v = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + range * v);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
