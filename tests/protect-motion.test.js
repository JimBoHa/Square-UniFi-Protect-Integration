"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  protectMotionAlert,
  protectMotionReceiptStatus,
  protectMotionSettings,
  protectMotionSettingsRequest,
  protectMotionStateText,
  protectMotionWebhookUrl,
} = require("../app/static/protect-motion.js");

test("motion webhook URL follows the browser origin instead of a fixed LAN IP", () => {
  assert.equal(
    protectMotionWebhookUrl(
      "https://10.23.45.67:8000",
      "/webhooks/protect/motion",
    ),
    "https://10.23.45.67:8000/webhooks/protect/motion",
  );
  assert.equal(
    protectMotionWebhookUrl(
      "https://register-app.lan:9443",
      "/webhooks/protect/motion",
    ),
    "https://register-app.lan:9443/webhooks/protect/motion",
  );
  assert.throws(
    () => protectMotionWebhookUrl(
      "https://register-app.lan",
      "https://attacker.example/webhook",
    ),
    /this app origin/,
  );
});

test("motion settings normalize server names without exposing an absent token", () => {
  assert.deepEqual(
    protectMotionSettings({
      enabled: true,
      camera_id: "barn-east",
      camera_name: "Barn East",
      match_window_seconds: 12,
      grace_seconds: 75,
      retention_days: 45,
      webhook_path: "/webhooks/protect/motion",
      webhook_header: "X-SPI-Webhook-Token",
      token_configured: true,
      last_event_ms: 1234,
    }),
    {
      enabled: true,
      cameraId: "barn-east",
      cameraName: "Barn East",
      matchWindowSeconds: 12,
      graceSeconds: 75,
      retentionDays: 45,
      webhookPath: "/webhooks/protect/motion",
      webhookHeader: "X-SPI-Webhook-Token",
      webhookToken: "",
      tokenConfigured: true,
      lastEventMs: 1234,
    },
  );
});

test("motion settings request converts bounded number inputs", () => {
  assert.deepEqual(
    protectMotionSettingsRequest({
      cameraId: "barn-east",
      matchWindowSeconds: "15",
      graceSeconds: "90",
      retentionDays: "30",
      rotateToken: true,
    }),
    {
      camera_id: "barn-east",
      match_window_seconds: 15,
      grace_seconds: 90,
      retention_days: 30,
      rotate_token: true,
    },
  );
});

test("motion receipt status reports exact machine time and a bounded relative age", () => {
  const eventMs = Date.UTC(2026, 7, 8, 20, 0, 0);
  assert.deepEqual(
    protectMotionReceiptStatus(eventMs, eventMs + 90_000),
    {
      received: true,
      timestampMs: eventMs,
      dateTime: "2026-08-08T20:00:00.000Z",
      relativeText: "1 minute ago",
    },
  );
  assert.equal(
    protectMotionReceiptStatus(eventMs, eventMs + 2 * 3_600_000).relativeText,
    "2 hours ago",
  );
  assert.equal(
    protectMotionReceiptStatus(eventMs, eventMs + 3 * 86_400_000).relativeText,
    "3 days ago",
  );
  assert.equal(
    protectMotionReceiptStatus(eventMs, eventMs - 1).relativeText,
    "just now",
  );
});

test("motion receipt status rejects absent and invalid timestamps", () => {
  const expected = {
    received: false,
    timestampMs: null,
    dateTime: "",
    relativeText: "No authenticated motion notification has been received yet.",
  };
  assert.deepEqual(protectMotionReceiptStatus(null, 1234), expected);
  assert.deepEqual(protectMotionReceiptStatus(-1, 1234), expected);
  assert.deepEqual(protectMotionReceiptStatus(Number.MAX_SAFE_INTEGER, 1234), expected);
});

test("motion alert states use explicit safe labels", () => {
  assert.equal(protectMotionStateText({ state: "pending" }), "Waiting for Square");
  assert.equal(
    protectMotionStateText({ state: "flagged" }),
    "No matching transaction",
  );
  assert.equal(
    protectMotionStateText({ state: "matched" }),
    "Matched to transaction",
  );
  assert.equal(protectMotionAlert({ state: "untrusted" }).state, "pending");
});

test("motion UI loads helper first and renders provider text without HTML", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );
  assert.ok(html.indexOf("/protect-motion.js") >= 0);
  assert.ok(html.indexOf("/protect-motion.js") < html.indexOf("/app.js"));
  assert.match(html, /id="protect-motion-camera"/);
  assert.match(html, /Last UniFi motion webhook received/);
  assert.match(html, /id="protect-motion-last-event"/);
  assert.match(html, /id="motion-alerts-panel"/);
  assert.match(app, /!\$\("#view-settings"\)\.hidden/);
  assert.match(app, /camera\.textContent = event\.camera_name/);
  assert.match(app, /alarm\.textContent = `Protect alarm:/);
  assert.doesNotMatch(app, /motion-alert[\s\S]{0,500}innerHTML/);
});
