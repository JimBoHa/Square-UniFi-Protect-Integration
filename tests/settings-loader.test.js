"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { createLatestSettingsLoader } = require(
  "../app/static/settings-loader.js"
);

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("only the newest settings load renders after out-of-order responses", async () => {
  const older = deferred();
  const newer = deferred();
  const responses = [older, newer];
  const rendered = [];
  const loadSettings = createLatestSettingsLoader(
    () => responses.shift().promise,
    (settings) => rendered.push(settings),
  );

  const olderLoad = loadSettings();
  const newerLoad = loadSettings();
  newer.resolve("new settings");
  assert.equal(await newerLoad, true);
  older.resolve("stale settings");
  assert.equal(await olderLoad, false);
  assert.deepEqual(rendered, ["new settings"]);
});

test("settings loader is available before the application script", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  const loaderIndex = html.indexOf("/settings-loader.js");
  const appIndex = html.indexOf("/app.js");
  assert.ok(loaderIndex >= 0);
  assert.ok(appIndex >= 0);
  assert.ok(loaderIndex < appIndex);
});
