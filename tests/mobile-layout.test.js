"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("narrow layouts stack fixed-width rows and constrain controls", () => {
  const css = fs.readFileSync(
    path.join(__dirname, "../app/static/style.css"),
    "utf8",
  );
  const mediaStart = css.indexOf("@media (max-width: 520px)");
  const mobile = css.slice(mediaStart);

  assert.ok(mediaStart >= 0);
  assert.match(mobile, /header \{[\s\S]*flex-direction: column/);
  assert.match(
    mobile,
    /nav \{[\s\S]*grid-template-columns: repeat\(3, minmax\(0, 1fr\)\)/,
  );
  assert.match(mobile, /nav button \{[^}]*margin-left: 0;[^}]*min-width: 0/);
  assert.match(mobile, /nav\[hidden\] \{ display: none; \}/);
  assert.match(
    mobile,
    /form, label, input, select, button \{ min-width: 0; max-width: 100%; \}/,
  );
  assert.match(
    mobile,
    /\.mapping-row \{[\s\S]*flex-direction: column/,
  );
  assert.match(
    mobile,
    /\.mapping-row \.loc \{ min-width: 0; width: 100%; \}/,
  );
  assert.match(mobile, /\.mapping-row select \{ width: 100%; \}/);
  assert.match(
    mobile,
    /\.txn \{[\s\S]*grid-template-columns: minmax\(0, 1fr\)/,
  );
  assert.match(
    mobile,
    /\.txn \.thumb \{ width: 100%; height: auto; aspect-ratio: 16 \/ 9; \}/,
  );
  assert.match(mobile, /\.txn \.amount \{ min-width: 0; \}/);
  assert.match(mobile, /\.toolbar \{ flex-wrap: wrap/);
});

test("desktop fixed-size layout remains outside the mobile override", () => {
  const css = fs.readFileSync(
    path.join(__dirname, "../app/static/style.css"),
    "utf8",
  );
  const mediaStart = css.indexOf("@media (max-width: 520px)");
  const desktop = css.slice(0, mediaStart);

  assert.match(desktop, /\.mapping-row \.loc \{ min-width: 280px/);
  assert.match(desktop, /width: 160px; height: 90px/);
  assert.match(desktop, /header \{[\s\S]*justify-content: space-between/);
});
