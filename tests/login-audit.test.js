"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { loginAuditPage } = require("../app/static/login-audit.js");

test("audit payload parsing keeps only bounded display fields and cursor", () => {
  const page = loginAuditPage({
    events: [
      {
        id: 9,
        user_id: 2,
        username: "barn.viewer",
        role: "viewer",
        client_ip: "192.0.2.5",
        logged_in_at: 123.5,
        password_hash: "must-not-pass-through",
      },
      {
        id: 8,
        user_id: 2,
        username: "bad-role",
        role: "owner",
        client_ip: "192.0.2.6",
        logged_in_at: 123,
      },
    ],
    next_before_id: 9,
  });
  assert.deepEqual(page, {
    events: [{
      id: 9,
      userId: 2,
      username: "barn.viewer",
      role: "viewer",
      clientIp: "192.0.2.5",
      loggedInAt: 123.5,
    }],
    nextBeforeId: 9,
  });
  assert.deepEqual(loginAuditPage({}), { events: [], nextBeforeId: null });
});

test("administrator UI paginates and renders login history as text", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");

  assert.ok(html.indexOf("/login-audit.js") < html.indexOf("/app.js"));
  assert.match(html, /id="login-audit-list"/);
  assert.match(html, /id="login-audit-more" hidden/);
  assert.match(app, /api\(`\/api\/login-audit\?limit=100\$\{cursor\}`\)/);
  assert.match(app, /username\.textContent = event\.username/);
  assert.match(app, /detail\.textContent = `\$\{when\} · \$\{event\.clientIp\}`/);
  assert.match(app, /loginAuditEvents = reset[\s\S]*\.\.\.loginAuditEvents/);
});
