"use strict";

const TRANSACTION_QUERY_MAX_LENGTH = 64;

function normalizeTransactionFilters(query, status) {
  return Object.freeze({
    query: String(query || "").trim(),
    status: String(status || ""),
  });
}

function transactionFilterQuery(filters) {
  const params = new URLSearchParams();
  if (filters.query) params.set("q", filters.query);
  if (filters.status) params.set("status", filters.status);
  return params.toString();
}

function transactionFiltersActive(filters) {
  return Boolean(filters.query || filters.status);
}

if (typeof module !== "undefined") {
  module.exports = {
    TRANSACTION_QUERY_MAX_LENGTH,
    normalizeTransactionFilters,
    transactionFilterQuery,
    transactionFiltersActive,
  };
}
