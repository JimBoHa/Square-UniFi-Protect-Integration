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
    lastEventMs: Number.isSafeInteger(value.last_event_ms) &&
      value.last_event_ms >= 0 &&
      Number.isFinite(new Date(value.last_event_ms).valueOf())
      ? value.last_event_ms : null,
  };
}

function protectMotionReceiptStatus(lastEventMs, nowMs = Date.now()) {
  const eventDate = new Date(lastEventMs);
  if (
    !Number.isSafeInteger(lastEventMs) ||
    lastEventMs < 0 ||
    !Number.isFinite(eventDate.valueOf())
  ) {
    return {
      received: false,
      timestampMs: null,
      dateTime: "",
      relativeText: "No authenticated motion notification has been received yet.",
    };
  }

  const safeNowMs = Number.isFinite(nowMs) ? nowMs : lastEventMs;
  const ageMs = Math.max(0, safeNowMs - lastEventMs);
  const minutes = Math.floor(ageMs / 60_000);
  const hours = Math.floor(ageMs / 3_600_000);
  const days = Math.floor(ageMs / 86_400_000);
  let relativeText = "just now";
  if (days >= 1) relativeText = `${days} day${days === 1 ? "" : "s"} ago`;
  else if (hours >= 1) relativeText = `${hours} hour${hours === 1 ? "" : "s"} ago`;
  else if (minutes >= 1) relativeText = `${minutes} minute${minutes === 1 ? "" : "s"} ago`;

  return {
    received: true,
    timestampMs: lastEventMs,
    dateTime: eventDate.toISOString(),
    relativeText,
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
    protectMotionReceiptStatus,
    protectMotionSettings,
    protectMotionSettingsRequest,
    protectMotionStateText,
    protectMotionWebhookUrl,
  };
}
