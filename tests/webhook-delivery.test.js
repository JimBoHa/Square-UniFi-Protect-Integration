"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { webhookDeliveryHint, webhookDuration } = require(
  "../app/static/webhook-delivery.js"
);

test("webhook delivery duration stays readable from milliseconds to minutes", () => {
  assert.equal(webhookDuration(285), "285 ms");
  assert.equal(webhookDuration(4434), "4.43 s");
  assert.equal(webhookDuration(65_000), "1.1 min");
});

test("webhook hint reports lag, accepted events, and ignored duplicates", () => {
  assert.equal(
    webhookDeliveryHint({
      last_delivery_lag_ms: 285,
      accepted_payment_count: 1000,
      duplicate_count: 2,
    }),
    "Square delivered in 285 ms · 1,000 payment events accepted · 2 duplicates ignored",
  );
  assert.match(
    webhookDeliveryHint({
      last_delivery_lag_ms: -1200,
      accepted_payment_count: 1,
      duplicate_count: 0,
    }),
    /Host clock was 1\.20 s behind Square/,
  );
});

test("webhook helper loads before browser entry point", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  assert.ok(html.indexOf("/webhook-delivery.js") >= 0);
  assert.ok(html.indexOf("/webhook-delivery.js") < html.indexOf("/app.js"));
});
