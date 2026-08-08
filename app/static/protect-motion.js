"use strict";

const PROTECT_MOTION_STATES = new Set(["pending", "flagged", "matched"]);

function protectMotionWebhookUrl(origin, path) {
  const url = new URL(path || "/webhooks/protect/motion", origin);
  if (url.origin !== new URL(origin).origin) {
    throw new Error("Motion webhook path must use this app origin");
  }
  return url.href;
}

function protectMotionSettings(payload) {
  const value = payload && typeof payload === "object" ? payload : {};
  return {
    enabled: value.enabled === true,
    cameraId: typeof value.camera_id === "string" ? value.camera_id : "",
    cameraName: typeof value.camera_name === "string" ? value.camera_name : "",
    matchWindowSeconds: Number.isInteger(value.match_window_seconds)
      ? value.match_window_seconds : 15,
    graceSeconds: Number.isInteger(value.grace_seconds)
      ? value.grace_seconds : 90,
    retentionDays: Number.isInteger(value.retention_days)
      ? value.retention_days : 30,
    webhookPath: typeof value.webhook_path === "string"
      ? value.webhook_path : "/webhooks/protect/motion",
    webhookHeader: typeof value.webhook_header === "string"
      ? value.webhook_header : "X-SPI-Webhook-Token",
    webhookToken: typeof value.webhook_token === "string"
      ? value.webhook_token : "",
    tokenConfigured: value.token_configured === true,
    lastEventMs: Number.isInteger(value.last_event_ms)
      ? value.last_event_ms : null,
  };
}

function protectMotionSettingsRequest({
  cameraId,
  matchWindowSeconds,
  graceSeconds,
  retentionDays,
  rotateToken,
}) {
  return {
    camera_id: String(cameraId || ""),
    match_window_seconds: Number(matchWindowSeconds),
    grace_seconds: Number(graceSeconds),
    retention_days: Number(retentionDays),
    rotate_token: rotateToken === true,
  };
}

function protectMotionAlert(event) {
  const value = event && typeof event === "object" ? event : {};
  return {
    ...value,
    state: PROTECT_MOTION_STATES.has(value.state) ? value.state : "pending",
  };
}

function protectMotionStateText(event) {
  const alert = protectMotionAlert(event);
  if (alert.state === "flagged") return "No matching transaction";
  if (alert.state === "matched") return "Matched to transaction";
  return "Waiting for Square";
}

if (typeof module !== "undefined") {
  module.exports = {
    protectMotionAlert,
    protectMotionSettings,
    protectMotionSettingsRequest,
    protectMotionStateText,
    protectMotionWebhookUrl,
  };
}
