"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  TRANSACTION_QUERY_MAX_LENGTH,
  normalizeTransactionFilters,
  transactionFilterQuery,
  transactionFiltersActive,
} = require("../app/static/transaction-filters.js");

test("transaction filters trim search and encode literal query data", () => {
  const filters = normalizeTransactionFilters("  PAY %_&42  ", "COMPLETED");

  assert.deepEqual(filters, { query: "PAY %_&42", status: "COMPLETED" });
  assert.equal(
    transactionFilterQuery(filters),
    "q=PAY+%25_%2642&status=COMPLETED",
  );
  assert.equal(transactionFiltersActive(filters), true);
  assert.equal(TRANSACTION_QUERY_MAX_LENGTH, 64);
});

test("empty transaction filters add no query parameters", () => {
  const filters = normalizeTransactionFilters("   ", "");

  assert.equal(transactionFilterQuery(filters), "");
  assert.equal(transactionFiltersActive(filters), false);
});

test("filter helper loads before the application entry point", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );

  const helperIndex = html.indexOf("/transaction-filters.js");
  const appIndex = html.indexOf("/app.js");
  assert.ok(helperIndex >= 0);
  assert.ok(helperIndex < appIndex);
  assert.match(html, /id="txn-filter-form"[^>]*role="search"/);
  assert.match(html, /id="txn-filter-help"/);
});

test("filter changes reset paging and bind every request to current filters", () => {
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );
  const css = fs.readFileSync(
    path.join(__dirname, "../app/static/style.css"),
    "utf8",
  );

  assert.match(app, /const requestedFilters = transactionFilters/);
  assert.match(app, /transactionFilterQuery\(requestedFilters\)/);
  assert.match(app, /snapshotParam.*filterParam/s);
  assert.match(
    app,
    /function applyTransactionFilters[\s\S]*transactionOffset = 0;[\s\S]*transactionSnapshot = null;/,
  );
  assert.match(app, /#txn-filter-form.*addEventListener\("submit"/);
  assert.match(app, /#txn-filter-clear.*addEventListener\("click"/);
  assert.match(app, /transactionId\.textContent = `ID \$\{txn\.id\}`/);
  assert.match(css, /\.txn \.txn-details \{ min-width: 0; overflow-wrap: anywhere; \}/);
});
