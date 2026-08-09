"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const app = fs.readFileSync(
  path.join(__dirname, "../app/static/app.js"),
  "utf8",
);

test("Sync now blocks duplicate submissions until request settles", () => {
  assert.match(app, /const syncNowButton = \$\("#sync-now"\)/);
  assert.match(app, /if \(syncNowButton\.disabled\) return/);
  assert.match(
    app,
    /syncNowButton\.disabled = true[\s\S]*finally \{\s*syncNowButton\.disabled = false/,
  );
});
