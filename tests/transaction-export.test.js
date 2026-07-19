"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const html = fs.readFileSync(
  path.join(__dirname, "../app/static/index.html"),
  "utf8",
);
const css = fs.readFileSync(
  path.join(__dirname, "../app/static/style.css"),
  "utf8",
);

test("transactions view exposes a native authenticated CSV download", () => {
  assert.match(
    html,
    /<a id="export-csv" href="\/api\/transactions\/export\.csv"[\s\S]*?download="square-protect-transactions\.csv">Download CSV<\/a>/,
  );
  assert.match(html, /<div class="toolbar-actions">/);
});

test("CSV download has visible keyboard focus styling", () => {
  assert.match(css, /#export-csv:focus-visible\s*{[^}]*outline:/);
});
