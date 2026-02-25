"use strict";
// PhishGuard content script — lightweight, no DOM modification
// Listens for messages from background to inject warnings if needed

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "INJECT_WARNING") {
    const banner = document.createElement("div");
    banner.style.cssText = [
      "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
      "background:#ff2d55", "color:#fff", "font-family:monospace",
      "font-size:14px", "font-weight:bold", "padding:12px 20px",
      "text-align:center", "letter-spacing:1px", "box-shadow:0 2px 20px rgba(255,45,85,0.5)",
    ].join(";");
    banner.textContent = "PHISHGUARD WARNING: This page may be a phishing attempt. Risk Score: " + msg.score + "/100";
    const close = document.createElement("button");
    close.textContent = " X ";
    close.style.cssText = "margin-left:12px;background:transparent;border:1px solid #fff;color:#fff;cursor:pointer;padding:2px 8px;border-radius:3px;";
    close.onclick = () => banner.remove();
    banner.appendChild(close);
    document.body.prepend(banner);
    sendResponse({ injected: true });
  }
});
