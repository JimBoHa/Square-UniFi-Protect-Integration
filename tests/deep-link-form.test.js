"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  applyDeepLinkSettings,
  createLatestDeepLinkSettingsLoader,
  deepLinkSettingsRequest,
} = require("../app/static/deep-link-form.js");

const defaultTemplate = "https://{host}/protect/timelapse/{camera_id}?start={ts_ms}";

test("default settings leave the override blank and explain the fallback", () => {
  const input = { value: "stale", placeholder: "" };
  const status = { textContent: "" };

  applyDeepLinkSettings(input, status, {
    template: "",
    default_template: defaultTemplate,
  });

  assert.equal(input.value, "");
  assert.equal(input.placeholder, defaultTemplate);
  assert.equal(status.textContent, `Using built-in default: ${defaultTemplate}`);
  assert.deepEqual(deepLinkSettingsRequest(input), { template: "" });
});

test("custom settings populate the field and submissions trim outer space", () => {
  const custom = "https://{host}/protect/{camera_id}?at={ts_ms}";
  const input = { value: "", placeholder: "" };
  const status = { textContent: "" };

  applyDeepLinkSettings(input, status, {
    template: custom,
    default_template: defaultTemplate,
  });
  assert.equal(input.value, custom);
  assert.match(status.textContent, /custom/);

  input.value = `  ${custom}  `;
  assert.deepEqual(deepLinkSettingsRequest(input), { template: custom });
});

test("only the newest deep-link settings load renders", async () => {
  const pending = [];
  const rendered = [];
  const loader = createLatestDeepLinkSettingsLoader(
    () => new Promise((resolve) => pending.push(resolve)),
    (settings) => rendered.push(settings.template),
  );

  const older = loader();
  const newer = loader();
  pending[1]({ template: "newer" });
  await newer;
  pending[0]({ template: "older" });
  await older;

  assert.deepEqual(rendered, ["newer"]);
});

test("saved settings invalidate an older in-flight load", async () => {
  let resolveLoad;
  const rendered = [];
  const loader = createLatestDeepLinkSettingsLoader(
    () => new Promise((resolve) => { resolveLoad = resolve; }),
    (settings) => rendered.push(settings.template),
  );

  const pendingLoad = loader();
  loader.invalidate();
  resolveLoad({ template: "stale" });
  await pendingLoad;

  assert.deepEqual(rendered, []);
});

test("app loads the form helper before its browser entry point", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  assert.ok(html.indexOf('/deep-link-form.js') >= 0);
  assert.ok(html.indexOf('/deep-link-form.js') < html.indexOf('/app.js'));
});
