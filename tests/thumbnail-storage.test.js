"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const html = fs.readFileSync(
  path.join(__dirname, "../app/static/index.html"),
  "utf8",
);
const app = fs.readFileSync(
  path.join(__dirname, "../app/static/app.js"),
  "utf8",
);

test("storage controls expose bounded compression and retention inputs", () => {
  assert.match(html, /id="thumbnail-jpeg-quality" min="30" max="95"/);
  assert.match(html, /id="thumbnail-max-dimension" min="320" max="3840"/);
  assert.match(html, /id="thumbnail-retention-days" min="0" max="3650"/);
  assert.match(html, /id="thumbnail-max-storage-mib" min="0" max="1048576"/);
});

test("retention warning explains bytes are removed but links remain", () => {
  assert.match(
    html,
    /permanently remove only thumbnail JPEGs[\s\S]*Transaction details and UniFi Protect timeline links remain/,
  );
  assert.match(html, /id="thumbnail-storage-status"[^>]*role="status"/);
});

test("storage form sends every policy field in an authenticated JSON body", () => {
  assert.match(app, /api\("\/api\/settings\/thumbnail-storage", \{/);
  for (const field of [
    "compression_enabled",
    "jpeg_quality",
    "max_dimension",
    "retention_days",
    "max_storage_mib",
  ]) {
    assert.match(app, new RegExp(`${field}:`));
  }
});

test("expired evidence has a distinct transaction-feed label", () => {
  assert.match(app, /expired: "thumbnail expired"/);
});
