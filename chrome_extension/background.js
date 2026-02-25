"use strict";

const API_BASE = "http://localhost:8000";

// Listen for messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "PHISHING_DETECTED") {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "PhishGuard Warning",
      message: "Phishing detected! Risk score: " + msg.score + "/100",
      priority: 2,
    });
    // Badge the extension icon red
    chrome.action.setBadgeText({ text: "!", tabId: msg.tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ff2d55", tabId: msg.tabId });
  }

  if (msg.type === "SCAN_URL") {
    fetch(API_BASE + "/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: msg.url }),
    })
      .then(r => r.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
  }
});

// Auto-scan on tab navigation (optional — disabled by default)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    // Clear badge on navigation
    chrome.action.setBadgeText({ text: "", tabId });
  }
});
