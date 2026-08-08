"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  accountRoleLabel,
  passwordPairError,
  userAccounts,
} = require("../app/static/user-management.js");

test("password confirmation is bounded and exact", () => {
  assert.equal(passwordPairError("short", "short"), "Password must be at least 8 characters.");
  assert.equal(passwordPairError("valid-password", "different"), "Passwords do not match.");
  assert.equal(
    passwordPairError("x".repeat(257), "x".repeat(257)),
    "Password must be no more than 256 characters.",
  );
  assert.equal(passwordPairError("valid-password", "valid-password"), "");
});

test("user payload parsing keeps only safe display fields", () => {
  const accounts = userAccounts({
    users: [
      {
        id: 2,
        username: "barn.viewer",
        role: "viewer",
        enabled: true,
        created_at: 123.5,
        current: false,
        password_hash: "must-not-pass-through",
      },
      { id: 3, username: "bad", role: "owner", enabled: true, created_at: 1 },
      { id: 0, username: "bad", role: "admin", enabled: true, created_at: 1 },
    ],
  });
  assert.deepEqual(accounts, [{
    id: 2,
    username: "barn.viewer",
    role: "viewer",
    enabled: true,
    createdAt: 123.5,
    current: false,
  }]);
  assert.equal(accountRoleLabel("admin"), "Administrator");
  assert.equal(accountRoleLabel("viewer"), "View only");
  assert.equal(accountRoleLabel("owner"), "Unknown role");
});

test("settings UI wires admin account creation and session-revoking reset", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");
  const css = fs.readFileSync(path.join(staticDir, "style.css"), "utf8");

  assert.ok(html.indexOf("/user-management.js") < html.indexOf("/app.js"));
  assert.match(html, /id="user-create-form"/);
  assert.match(html, /id="user-create-password-confirm"/);
  assert.match(app, /await api\("\/api\/users"\)/);
  assert.match(app, /api\(`\/api\/users\/\$\{account\.id\}\/password`/);
  assert.match(app, /if \(result\.current_session_revoked\)/);
  assert.match(app, /leaveAppForLogin\(account\.username\)/);
  assert.doesNotMatch(app, /innerHTML\s*=/);
  assert.match(css, /\.user-reset-form \{[\s\S]*grid-template-columns:/);
  assert.match(css, /@media \(max-width: 520px\)[\s\S]*\.user-reset-form \{ grid-template-columns: 1fr; \}/);
});
