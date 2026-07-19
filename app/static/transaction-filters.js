"use strict";

const TRANSACTION_QUERY_MAX_LENGTH = 64;

function normalizeTransactionFilters(query, status) {
  return Object.freeze({
    query: String(query || "").trim(),
    status: String(status || ""),
  });
}

function transactionQueryBody(filters, { limit, offset, snapshot = null }) {
  const body = { limit, offset };
  if (snapshot !== null) body.snapshot = snapshot;
  if (filters.query) body.q = filters.query;
  if (filters.status) body.status = filters.status;
  return body;
}

function transactionFiltersActive(filters) {
  return Boolean(filters.query || filters.status);
}

if (typeof module !== "undefined") {
  module.exports = {
    TRANSACTION_QUERY_MAX_LENGTH,
    normalizeTransactionFilters,
    transactionQueryBody,
    transactionFiltersActive,
  };
}
