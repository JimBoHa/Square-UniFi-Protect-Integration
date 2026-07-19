"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  refundPresentation,
  renderRefundStatus,
} = require("../app/static/format.js");

const fakeDocument = {
  createElement(tagName) {
    return { tagName: tagName.toUpperCase(), className: "", textContent: "" };
  },
};

test("renders partial refund as accessible visible text", () => {
  const node = renderRefundStatus(fakeDocument, {
    amount: 1000,
    currency: "USD",
    refunded_amount: 250,
  });

  assert.equal(node.tagName, "DIV");
  assert.equal(node.className, "refund-status partial");
  assert.match(node.textContent, /^Partially refunded: /);
});

test("renders full refund without replacing original amount wiring", () => {
  const presentation = refundPresentation({
    amount: 1000,
    currency: "USD",
    refunded_amount: 1000,
  });
  const appSource = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );

  assert.equal(presentation.className, "refund-status full");
  assert.match(presentation.textContent, /^Fully refunded: /);
  assert.match(
    appSource,
    /amount\.textContent = formatAmount\(txn\.amount, txn\.currency\)/,
  );
  assert.match(appSource, /when\.textContent = new Date\(txn\.ts_ms\)/);
  assert.match(appSource, /link\.href = txn\.deep_link/);
  assert.match(appSource, /renderRefundStatus\(document, txn\)/);
});

test("omits refund label for unchanged and invalid transactions", () => {
  assert.equal(renderRefundStatus(fakeDocument, {
    amount: 1000,
    currency: "USD",
    refunded_amount: 0,
  }), null);
  assert.equal(refundPresentation({
    amount: 1000,
    currency: "USD",
    refunded_amount: "250",
  }), null);
});
