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

if (typeof module !== "undefined") module.exports = { formatAmount };
