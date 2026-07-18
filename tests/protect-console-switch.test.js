"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  cameraMappingSelectId,
  protectConnectionMessage,
  protectConsoleSwitchTokenRequest,
  publishLatestSettingsLoad,
  publishCoherentSettingsLoad,
  settingsSnapshotMismatchAction,
  clearProtectConsoleView,
} = require("../app/static/protect-console-switch.js");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("console-switch confirmation requests a target-bound server token", () => {
  const settings = {
    host: "protect.example",
    username: "admin",
    password: "secret",
    verify_ssl: true,
    api_key: "not-forwarded",
  };
  assert.equal(protectConsoleSwitchTokenRequest({ checked: false }, settings), null);
  assert.deepEqual(protectConsoleSwitchTokenRequest({ checked: true }, settings), {
    host: "protect.example",
    username: "admin",
    password: "secret",
    verify_ssl: true,
  });
});

test("successful switch warns that cameras must be selected again", () => {
  const message = protectConnectionMessage({
    cameras: 2,
    alarm_configured: false,
    console_switched: true,
  });
  assert.match(message, /evidence were cleared/);
  assert.match(message, /select POS cameras again/);
});

test("same-host refresh does not claim that evidence was cleared", () => {
  const message = protectConnectionMessage({
    cameras: 2,
    alarm_configured: true,
    console_switched: false,
  });
  assert.match(message, /Alarm trigger enabled/);
  assert.doesNotMatch(message, /cleared/);
});

test("camera mapping controls get stable globally unique ids", () => {
  const settingsFallback = cameraMappingSelectId("mapping-rows", "LOC1", "");
  assert.equal(
    settingsFallback,
    cameraMappingSelectId("mapping-rows", "LOC1", ""),
  );
  assert.notEqual(
    settingsFallback,
    cameraMappingSelectId("mapping-rows", "LOC1", "fallback"),
  );
  assert.notEqual(
    settingsFallback,
    cameraMappingSelectId("wiz-mapping-rows", "LOC1", ""),
  );
  assert.notEqual(
    cameraMappingSelectId("mapping-rows", "LOC-1", "DEVICE-2"),
    cameraMappingSelectId("mapping-rows", "LOC", "1-DEVICE-2"),
  );
  assert.doesNotMatch(settingsFallback, /\s/);
});

test("generated camera selects use their visible text as a label", () => {
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );
  const buildStart = app.indexOf("function buildMappingRows");
  const buildEnd = app.indexOf("function collectMappings", buildStart);
  const build = app.slice(buildStart, buildEnd);

  assert.match(build, /const label = document\.createElement\("label"\)/);
  assert.match(build, /select\.id = cameraMappingSelectId\(/);
  assert.match(build, /label\.htmlFor = select\.id/);
  assert.ok(build.indexOf("label.htmlFor = select.id") < build.indexOf("row.appendChild(label)"));
});

test("older settings load cannot publish cameras with a newer generation", async () => {
  let latestLoad = 0;
  let published = null;
  const oldTail = deferred();

  async function loadSettings(cameraResult, tail) {
    const loadGeneration = ++latestLoad;
    const localCameraResult = await cameraResult;
    await tail;
    publishLatestSettingsLoad(loadGeneration, latestLoad, () => {
      published = localCameraResult;
    });
  }

  const oldLoad = loadSettings(
    Promise.resolve({ camera: "old-camera", generation: "G1" }),
    oldTail.promise,
  );
  await Promise.resolve();
  await loadSettings(
    Promise.resolve({ camera: "new-camera", generation: "G2" }),
    Promise.resolve(),
  );
  oldTail.resolve();
  await oldLoad;

  assert.deepEqual(published, { camera: "new-camera", generation: "G2" });
});

test("console switch invalidation suppresses a pending old settings load", async () => {
  let latestLoad = 1;
  let published = null;
  const oldTail = deferred();

  const oldLoad = (async () => {
    const loadGeneration = latestLoad;
    await oldTail.promise;
    publishLatestSettingsLoad(loadGeneration, latestLoad, () => {
      published = { camera: "old-camera", generation: "G1" };
    });
  })();

  latestLoad += 1;
  oldTail.resolve();
  await oldLoad;

  assert.equal(published, null);
});

test("old camera response reloads instead of rendering after console switch", () => {
  let published = false;
  const decision = publishCoherentSettingsLoad(
    1,
    1,
    {
      cameraGeneration: "protect-generation-1",
      locationRevision: "square-revision-2",
      mappingGeneration: "protect-generation-2",
      mappingRevision: "square-revision-2",
    },
    () => { published = true; },
  );

  assert.equal(decision, "reload");
  assert.equal(published, false);
});

test("old location response reloads instead of rendering after account switch", () => {
  let published = false;
  const decision = publishCoherentSettingsLoad(
    1,
    1,
    {
      cameraGeneration: "protect-generation-2",
      locationRevision: "square-revision-1",
      mappingGeneration: "protect-generation-2",
      mappingRevision: "square-revision-2",
    },
    () => { published = true; },
  );

  assert.equal(decision, "reload");
  assert.equal(published, false);
});

test("coherent provider snapshots publish mapping save generations", () => {
  let published = false;
  const decision = publishCoherentSettingsLoad(
    4,
    4,
    {
      cameraGeneration: "protect-generation-2",
      locationRevision: "square-revision-2",
      mappingGeneration: "protect-generation-2",
      mappingRevision: "square-revision-2",
    },
    () => { published = true; },
  );

  assert.equal(decision, "published");
  assert.equal(published, true);
});

test("snapshot mismatch retries once then requires a page reload", () => {
  assert.equal(settingsSnapshotMismatchAction(1), "retry");
  assert.equal(settingsSnapshotMismatchAction(0), "show-reload");
});

test("every settings load clears an old preview before provider reads", () => {
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );
  const loadStart = app.indexOf("async function fetchSettingsView");
  const clearView = app.indexOf("clearProtectConsoleView(", loadStart);
  const cameraRead = app.indexOf('api("/api/cameras"');

  assert.ok(loadStart >= 0);
  assert.ok(clearView > loadStart);
  assert.ok(cameraRead > clearView);
});

test("successful switch immediately clears old console camera UI", () => {
  const mappingRows = { textContent: "Old register → Old camera" };
  const saveButton = { hidden: false };
  const previewWrap = { hidden: false };
  const previewImage = {
    src: "/api/camera-preview/old-camera",
    removeAttribute(name) {
      assert.equal(name, "src");
      this.src = "";
    },
  };

  clearProtectConsoleView(
    mappingRows,
    saveButton,
    previewWrap,
    previewImage,
  );

  assert.equal(mappingRows.textContent, "");
  assert.equal(saveButton.hidden, true);
  assert.equal(previewWrap.hidden, true);
  assert.equal(previewImage.src, "");
});

test("console-switch helper loads before the app entry point", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../app/static/index.html"),
    "utf8",
  );
  assert.match(html, /id="protect-confirm-console-switch"/);
  assert.ok(html.indexOf('/protect-console-switch.js') >= 0);
  assert.ok(html.indexOf('/protect-console-switch.js') < html.indexOf('/app.js'));
  const app = fs.readFileSync(
    path.join(__dirname, "../app/static/app.js"),
    "utf8",
  );
  assert.match(app, /X-Protect-Console-Generation/);
  assert.match(app, /console-switch-token/);
  assert.match(app, /confirmationCheckbox\.checked = false/);
  assert.match(app, /if \(result\.console_switched\)[\s\S]*lastTransactionPayload = null/);
  assert.match(
    app,
    /if \(result\.console_switched\)[\s\S]*settingsLoadGeneration \+= 1[\s\S]*squareAccountRevision = ""[\s\S]*cameraMappingGeneration = ""/,
  );
  assert.match(
    app,
    /if \(result\.console_switched\)[\s\S]*renderTransactions\(\[\]\)[\s\S]*settingsReload = loadSettingsView\(\)[\s\S]*Promise\.all/,
  );
  assert.match(app, /loadTransactions\(\{ reset: true \}\)/);
  assert.match(app, /includeResponse: true/);
  assert.match(
    app,
    /api\("\/api\/camera-mapping", \{ includeResponse: true \}\)/,
  );
  assert.match(
    app,
    /if \(!settingsSnapshotsMatch\(settings\)\)[\s\S]*void loadSettingsView\(\)/,
  );
  assert.match(app, /Provider settings kept changing[\s\S]*Reload the page/);
});
