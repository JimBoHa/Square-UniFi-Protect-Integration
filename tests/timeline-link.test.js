"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("thumbnail and placeholder states share the accessible Protect timeline link", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");
  const css = fs.readFileSync(path.join(staticDir, "style.css"), "utf8");

  const helperStart = app.indexOf("function protectTimelineLink");
  const renderStart = app.indexOf("function renderTransactions");
  const helper = app.slice(helperStart, renderStart);
  const renderEnd = app.indexOf("function setTile", renderStart);
  const render = app.slice(renderStart, renderEnd);

  assert.ok(helperStart >= 0);
  assert.match(helper, /link\.href = txn\.deep_link/);
  assert.match(helper, /link\.target = "_blank"/);
  assert.match(helper, /link\.rel = "noopener noreferrer"/);
  assert.match(helper, /"aria-label"/);
  assert.match(helper, /new Date\(txn\.ts_ms\)\.toLocaleString\(\)/);
  assert.match(render, /thumb = protectTimelineLink\(txn, image\)/);
  assert.match(
    render,
    /thumb\.textContent = thumbnailLabels\[txn\.thumbnail_status\] \|\| "no footage";\s*if \(txn\.deep_link\) \{\s*thumb = protectTimelineLink\(txn, thumb\)/,
  );
  assert.match(css, /\.thumbnail-link:focus-visible/);
  assert.match(css, /\.thumbnail-link \.thumb\.placeholder \{ cursor: pointer; \}/);
});

test("linked placeholders retain capture-state text instead of implying an image", () => {
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );
  assert.match(app, /unmapped: "camera not mapped"/);
  assert.match(app, /queued: "footage queued"/);
  assert.match(app, /retrying: "capture retrying"/);
  assert.match(app, /thumb\.className = "thumb placeholder"/);
});
