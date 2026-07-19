"use strict";

function formatAmount(minorUnits, currency) {
  try {
    const formatter = new Intl.NumberFormat(undefined, {
      style: "currency",
      currency,
    });
    const fractionDigits = formatter.resolvedOptions().maximumFractionDigits;
    return formatter.format(minorUnits / (10 ** fractionDigits));
  } catch {
    return `${(minorUnits / 100).toFixed(2)} ${currency}`;
  }
}

function refundPresentation(txn) {
  const refunded = txn && txn.refunded_amount;
  const original = txn && txn.amount;
  if (!Number.isSafeInteger(refunded) || refunded <= 0 ||
      !Number.isSafeInteger(original) || original <= 0) {
    return null;
  }
  const fullyRefunded = refunded >= original;
  const state = fullyRefunded ? "full" : "partial";
  const label = fullyRefunded ? "Fully refunded" : "Partially refunded";
  return {
    className: `refund-status ${state}`,
    textContent: `${label}: ${formatAmount(refunded, txn.currency)}`,
  };
}

function renderRefundStatus(doc, txn) {
  const presentation = refundPresentation(txn);
  if (!presentation) return null;
  const status = doc.createElement("div");
  status.className = presentation.className;
  // Visible text communicates state without relying on color or an icon, and
  // remains part of the transaction card's accessible reading order.
  status.textContent = presentation.textContent;
  return status;
}

if (typeof module !== "undefined") {
  module.exports = { formatAmount, refundPresentation, renderRefundStatus };
}
