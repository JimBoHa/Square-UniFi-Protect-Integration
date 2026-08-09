"use strict";

function nonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function protectAlarmStatus(payload) {
  const value = payload && typeof payload === "object" ? payload : {};
  return {
    configured: value.configured === true,
    triggerId: typeof value.trigger_id === "string" ? value.trigger_id : "",
    pending: nonnegativeInteger(value.pending) || 0,
    inProgress: nonnegativeInteger(value.in_progress) || 0,
    delivered: nonnegativeInteger(value.delivered) || 0,
    lastDeliveredAtMs: nonnegativeInteger(value.last_delivered_at_ms),
    testAcceptedAtMs: nonnegativeInteger(value.test_accepted_at_ms),
  };
}

function protectFlagDelivery(transaction) {
  const value = transaction && typeof transaction === "object"
    ? transaction : {};
  const deliveredAtMs = nonnegativeInteger(
    value.protect_flag_delivered_at_ms,
  );
  const offsetMs = Number.isSafeInteger(value.protect_flag_offset_ms)
    ? value.protect_flag_offset_ms : null;
  return { deliveredAtMs, offsetMs };
}

function formatSignedSeconds(milliseconds) {
  if (!Number.isSafeInteger(milliseconds)) return "";
  const seconds = milliseconds / 1000;
  const sign = seconds > 0 ? "+" : seconds < 0 ? "−" : "";
  return `${sign}${Math.abs(seconds).toFixed(3)}s`;
}

if (typeof module !== "undefined") {
  module.exports = {
    formatSignedSeconds,
    protectAlarmStatus,
    protectFlagDelivery,
  };
}
