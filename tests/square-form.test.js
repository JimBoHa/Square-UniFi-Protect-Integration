"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  resetSquareWebhookFields,
  squareWebhookRequestFields,
} = require("../app/static/square-form.js");

function formFields(key, url, clearWebhook) {
  return {
    key: { value: key },
    url: { value: url },
    clear: { checked: clearWebhook },
  };
}

function requestFields(form) {
  return squareWebhookRequestFields(form.key, form.url, form.clear);
}

function resetFields(form) {
  resetSquareWebhookFields(form.key, form.url, form.clear);
}

test("successful webhook save leaves a safe normal re-save", () => {
  const form = formFields(
    "  signature-key  ",
    "  https://example.test/webhooks/square  ",
    false,
  );
  assert.deepEqual(requestFields(form), {
    webhook_signature_key: "signature-key",
    webhook_url: "https://example.test/webhooks/square",
    clear_webhook: false,
  });

  resetFields(form);
  assert.deepEqual(requestFields(form), {
    webhook_signature_key: "",
    webhook_url: "",
    clear_webhook: false,
  });
});

test("remove flow blanks stale credentials and resets after success", () => {
  const form = formFields(
    "stale-signature-key",
    "https://example.test/webhooks/square",
    true,
  );
  assert.deepEqual(requestFields(form), {
    webhook_signature_key: "",
    webhook_url: "",
    clear_webhook: true,
  });

  resetFields(form);
  assert.equal(form.key.value, "");
  assert.equal(form.url.value, "");
  assert.equal(form.clear.checked, false);
});

test("Square form helper is available before the application script", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  const helperIndex = html.indexOf("/square-form.js");
  const appIndex = html.indexOf("/app.js");
  assert.ok(helperIndex >= 0);
  assert.ok(appIndex >= 0);
  assert.ok(helperIndex < appIndex);
});
