"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { frameOffsetText, frameOffsetTitle } = require(
  "../app/static/frame-offset.js"
);

test("frame offsets retain millisecond precision and direction", () => {
  assert.equal(frameOffsetText(-4434), "UniFi frame −4.434 s");
  assert.equal(frameOffsetText(715), "UniFi frame +0.715 s");
  assert.equal(frameOffsetText(0), "UniFi frame 0.000 s");
});

test("missing or invalid measurements stay hidden", () => {
  assert.equal(frameOffsetText(null), "");
  assert.equal(frameOffsetText(undefined), "");
  assert.equal(frameOffsetText("not-a-number"), "");
});

test("offset tooltip states the source, relation, and precision", () => {
  assert.match(frameOffsetTitle(-4434), /burned-in UniFi timestamp/i);
  assert.match(frameOffsetTitle(-4434), /4\.434 seconds before/);
  assert.match(frameOffsetTitle(715), /0\.715 seconds after/);
  assert.match(frameOffsetTitle(0), /0\.000 seconds at/);
  assert.match(frameOffsetTitle(0), /whole-second frame precision/);
});

test("frame offset helper loads before the browser entry point", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  assert.ok(html.indexOf("/frame-offset.js") >= 0);
  assert.ok(html.indexOf("/frame-offset.js") < html.indexOf("/app.js"));
});
