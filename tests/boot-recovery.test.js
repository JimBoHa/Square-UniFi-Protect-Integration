"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  bootFailureMessage,
  isSessionExpiredError,
  sessionExpiredError,
} = require("../app/static/boot-recovery.js");

test("session expiry remains distinct from startup failures", () => {
  const expired = sessionExpiredError();
  assert.equal(expired.message, "Please log in");
  assert.equal(isSessionExpiredError(expired), true);
  assert.equal(isSessionExpiredError(new Error("API unavailable")), false);
  assert.equal(isSessionExpiredError(null), false);
});

test("startup failures provide an actionable retry message", () => {
  assert.equal(
    bootFailureMessage(new Error("Request failed (500)")),
    "Could not load the application: Request failed (500). " +
      "Check the server connection and logs, then try again.",
  );
  assert.match(bootFailureMessage({}), /Unexpected startup error/);
  assert.match(bootFailureMessage({}), /try again/);
});

test("boot failures render a retry view without replacing login handling", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");

  assert.match(html, /id="view-boot-error"/);
  assert.match(html, /id="boot-error-detail" role="alert"/);
  assert.match(html, /id="boot-retry">Try again/);
  assert.ok(html.indexOf("/boot-recovery.js") < html.indexOf("/app.js"));
  assert.match(app, /status = await api\("\/api\/status"\)/);
  assert.match(
    app,
    /status = await api\("\/api\/status"\);[\s\S]*catch \(err\) \{[\s\S]*showBootFailure\(err\)/,
  );
  assert.match(
    app,
    /catch \(err\) \{\s*if \(isSessionExpiredError\(err\)\) return;\s*showBootFailure\(err\)/,
  );
  assert.match(app, /show\("#view-boot-error"\)/);
  assert.match(app, /"#boot-retry"\)\.addEventListener\("click"/);
});
