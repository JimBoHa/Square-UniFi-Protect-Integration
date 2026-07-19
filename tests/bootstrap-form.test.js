"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  bootstrapTransportError,
  isLoopbackBrowserHostname,
} = require("../app/static/bootstrap-form.js");

const html = fs.readFileSync(
  path.join(__dirname, "../app/static/index.html"),
  "utf8",
);
const app = fs.readFileSync(
  path.join(__dirname, "../app/static/app.js"),
  "utf8",
);

test("setup form requires the one-time secret and explains its source", () => {
  assert.match(html, /id="setup-bootstrap-secret"/);
  assert.match(html, /One-time bootstrap secret/);
  assert.match(html, /SPI_BOOTSTRAP_SECRET/);
  assert.match(html, /server console at startup/);
  assert.match(
    html,
    /id="setup-bootstrap-secret"[^>]*\brequired\b/,
  );
});

test("setup sends and clears the bootstrap secret without putting it in a URL", () => {
  assert.match(
    app,
    /bootstrap_secret:\s*bootstrapSecret/,
  );
  assert.match(app, /\$\("#setup-bootstrap-secret"\)\.value = ""/);
  assert.doesNotMatch(app, /\/api\/setup\?[^"']*bootstrap/i);
});

test("remote HTTP setup is blocked before fetch", () => {
  assert.match(
    bootstrapTransportError(
      { protocol: "http:", hostname: "pos.example.test" },
    ),
    /requires HTTPS/,
  );
  assert.equal(
    bootstrapTransportError(
      { protocol: "https:", hostname: "pos.example.test" },
    ),
    "",
  );
});

test("direct local HTTP may submit the mandatory secret", () => {
  assert.equal(
    bootstrapTransportError(
      { protocol: "http:", hostname: "localhost" },
    ),
    "",
  );
});

test("only literal browser loopback hosts qualify as local", () => {
  for (const host of ["localhost", "127.0.0.1", "127.4.3.2", "[::1]"]) {
    assert.equal(isLoopbackBrowserHostname(host), true, host);
  }
  for (const host of ["0.0.0.0", "localhost.example", "pos.example.test"]) {
    assert.equal(isLoopbackBrowserHostname(host), false, host);
  }
});

test("bootstrap helper loads before the browser entry point", () => {
  assert.ok(html.indexOf('/bootstrap-form.js') >= 0);
  assert.ok(html.indexOf('/bootstrap-form.js') < html.indexOf('/app.js'));
});
