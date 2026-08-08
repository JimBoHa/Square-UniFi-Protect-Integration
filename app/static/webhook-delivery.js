"use strict";

function webhookDuration(milliseconds) {
  const value = Math.abs(Number(milliseconds));
  if (!Number.isFinite(value)) return "";
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60_000) return `${(value / 1000).toFixed(value < 10_000 ? 2 : 1)} s`;
  return `${(value / 60_000).toFixed(1)} min`;
}

function webhookDeliveryHint(webhook) {
  if (!webhook || typeof webhook !== "object") return "";
  const hints = [];
  const rawLag = webhook.last_delivery_lag_ms;
  const lag = Number(rawLag);
  if (
    rawLag !== null
    && rawLag !== undefined
    && rawLag !== ""
    && Number.isFinite(lag)
  ) {
    const duration = webhookDuration(lag);
    hints.push(
      lag >= 0
        ? `Square delivered in ${duration}`
        : `Host clock was ${duration} behind Square`,
    );
  }
  const accepted = Number(webhook.accepted_payment_count);
  if (Number.isSafeInteger(accepted) && accepted > 0) {
    const noun = accepted === 1 ? "payment event" : "payment events";
    hints.push(`${accepted.toLocaleString()} ${noun} accepted`);
  }
  const duplicates = Number(webhook.duplicate_count);
  if (Number.isSafeInteger(duplicates) && duplicates > 0) {
    const noun = duplicates === 1 ? "duplicate" : "duplicates";
    hints.push(`${duplicates.toLocaleString()} ${noun} ignored`);
  }
  return hints.join(" · ");
}

if (typeof module !== "undefined") {
  module.exports = { webhookDeliveryHint, webhookDuration };
}
