"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  formatSignedSeconds,
  protectAlarmStatus,
  protectFlagDelivery,
} = require("../app/static/protect-alarm.js");

test("transaction flag status accepts only bounded display values", () => {
  assert.deepEqual(
    protectAlarmStatus({
      configured: true,
      trigger_id: "square-sale",
      pending: 2,
      in_progress: 1,
      delivered: 9,
      last_delivered_at_ms: 1234,
      test_accepted_at_ms: 2345,
    }),
    {
      configured: true,
      triggerId: "square-sale",
      pending: 2,
      inProgress: 1,
      delivered: 9,
      lastDeliveredAtMs: 1234,
      testAcceptedAtMs: 2345,
    },
  );
  assert.deepEqual(
    protectAlarmStatus({
      pending: -1,
      delivered: "9",
      last_delivered_at_ms: Number.MAX_VALUE,
    }),
    {
      configured: false,
      triggerId: "",
      pending: 0,
      inProgress: 0,
      delivered: 0,
      lastDeliveredAtMs: null,
      testAcceptedAtMs: null,
    },
  );
});

test("transaction cards normalize and format measured Protect flag offset", () => {
  assert.deepEqual(
    protectFlagDelivery({
      protect_flag_delivered_at_ms: 12_345,
      protect_flag_offset_ms: 2345,
    }),
    { deliveredAtMs: 12_345, offsetMs: 2345 },
  );
  assert.equal(formatSignedSeconds(2345), "+2.345s");
  assert.equal(formatSignedSeconds(-2345), "−2.345s");
  assert.equal(formatSignedSeconds(0), "0.000s");
  assert.equal(formatSignedSeconds(null), "");
});

test("transaction flag UI loads helper first and confirms active test actions", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );

  assert.ok(html.indexOf("/protect-alarm.js") >= 0);
  assert.ok(html.indexOf("/protect-alarm.js") < html.indexOf("/app.js"));
  assert.match(html, /id="protect-test-alarm"/);
  assert.match(html, /data-tile="transaction-flags"/);
  assert.match(app, /window\.confirm\(/);
  assert.match(app, /protect-alarm-status"\)\.textContent/);
  assert.match(app, /flag\.textContent = offset/);
});
