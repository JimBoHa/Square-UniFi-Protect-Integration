"use strict";

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
  module.exports = { squareWebhookRequestFields, resetSquareWebhookFields };
}
