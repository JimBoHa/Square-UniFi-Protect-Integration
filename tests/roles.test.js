"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  applyRoleInterface,
  isAdmin,
  roleLabel,
  sessionUser,
} = require("../app/static/roles.js");

test("session identity accepts only known server roles", () => {
  assert.deepEqual(
    sessionUser({ user: { username: "admin", role: "admin", secret: "omit" } }),
    { username: "admin", role: "admin" },
  );
  assert.deepEqual(sessionUser({ username: "watch", role: "viewer" }), {
    username: "watch",
    role: "viewer",
  });
  assert.equal(sessionUser({ user: { username: "root", role: "owner" } }), null);
  assert.equal(sessionUser({ user: { username: "", role: "admin" } }), null);
  assert.equal(sessionUser(null), null);
});

test("role interface exposes administration controls only to administrators", () => {
  const controls = [{ hidden: false }, { hidden: false }];
  const identity = { textContent: "" };
  const viewer = { username: "barn.viewer", role: "viewer" };

  assert.equal(applyRoleInterface(viewer, controls, identity), false);
  assert.deepEqual(controls.map((control) => control.hidden), [true, true]);
  assert.equal(identity.textContent, "barn.viewer · View only");
  assert.equal(isAdmin(viewer), false);

  const admin = { username: "admin", role: "admin" };
  assert.equal(applyRoleInterface(admin, controls, identity), true);
  assert.deepEqual(controls.map((control) => control.hidden), [false, false]);
  assert.equal(identity.textContent, "admin · Administrator");
  assert.equal(roleLabel(null), "");
});

test("frontend resolves session role before loading privileged views", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");

  assert.ok(html.indexOf("/roles.js") < html.indexOf("/app.js"));
  assert.match(html, /id="login-username"[^>]*autocomplete="username"/);
  assert.match(html, /data-view="settings" data-admin-only hidden/);
  assert.match(html, /id="sync-now" data-admin-only hidden/);
  assert.match(app, /const session = await api\("\/api\/session"\)/);
  assert.doesNotMatch(app, /Probe an authed endpoint[\s\S]*api\("\/api\/camera-mapping"\)/);
  assert.match(app, /if \(isAdmin\(currentUser\)\) loadSettingsView\(\)/);
  assert.match(
    app,
    /if \(isAdmin\(currentUser\) && await maybeStartWizard\(\)\)/,
  );
});
