"use strict";

function squareOAuthResultFeedback(search) {
  const result = new URLSearchParams(search).get("square_oauth");
  if (result === "connected") {
    return {
      text: "Square account connected via OAuth.",
      kind: "ok",
    };
  }
  if (result === "denied") {
    return {
      text: "Square connection was canceled. Open Settings and press “Connect with Square” to try again.",
      kind: "",
    };
  }
  return null;
}

function squareWebhookRequestFields(keyInput, urlInput, clearInput) {
  const clearWebhook = clearInput.checked;
  return {
    webhook_signature_key: clearWebhook ? "" : keyInput.value.trim(),
    webhook_url: clearWebhook ? "" : urlInput.value.trim(),
    clear_webhook: clearWebhook,
  };
}

function resetSquareWebhookFields(keyInput, urlInput, clearInput) {
  keyInput.value = "";
  urlInput.value = "";
  clearInput.checked = false;
}

if (typeof module !== "undefined") {
  module.exports = {
    resetSquareWebhookFields,
    squareOAuthResultFeedback,
    squareWebhookRequestFields,
  };
}
