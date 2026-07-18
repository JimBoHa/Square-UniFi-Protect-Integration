"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  activateViewState,
  navViewName,
} = require("../app/static/nav-view.js");

function button(view, initiallyActive = false) {
  const classes = new Set(initiallyActive ? ["active"] : []);
  const attributes = new Map();
  return {
    dataset: { view },
    classList: {
      contains: (name) => classes.has(name),
      toggle(name, enabled) {
        if (enabled) classes.add(name);
        else classes.delete(name);
      },
    },
    getAttribute: (name) => attributes.get(name) || null,
    removeAttribute: (name) => attributes.delete(name),
    setAttribute: (name, value) => attributes.set(name, value),
  };
}

test("view activation keeps sections and navigation semantics synchronized", () => {
  const transactions = { id: "view-transactions", hidden: true };
  const settings = { id: "view-settings", hidden: true };
  const login = { id: "view-login", hidden: true };
  const sections = [transactions, settings, login];
  const transactionsButton = button("transactions", true);
  const settingsButton = button("settings");
  const buttons = [transactionsButton, settingsButton];

  assert.equal(activateViewState(sections, settings, buttons), "settings");
  assert.equal(settings.hidden, false);
  assert.equal(transactions.hidden, true);
  assert.equal(settingsButton.classList.contains("active"), true);
  assert.equal(settingsButton.getAttribute("aria-current"), "page");
  assert.equal(transactionsButton.classList.contains("active"), false);
  assert.equal(transactionsButton.getAttribute("aria-current"), null);

  assert.equal(activateViewState(sections, transactions, buttons), "transactions");
  assert.equal(transactions.hidden, false);
  assert.equal(settings.hidden, true);
  assert.equal(transactionsButton.classList.contains("active"), true);
  assert.equal(transactionsButton.getAttribute("aria-current"), "page");
  assert.equal(settingsButton.classList.contains("active"), false);

  assert.equal(activateViewState(sections, login, buttons), "");
  assert.equal(login.hidden, false);
  assert.equal(transactionsButton.classList.contains("active"), false);
  assert.equal(settingsButton.classList.contains("active"), false);
  assert.equal(transactionsButton.getAttribute("aria-current"), null);
  assert.equal(settingsButton.getAttribute("aria-current"), null);
});

test("only app navigation sections map to a current nav view", () => {
  assert.equal(navViewName({ id: "view-transactions" }), "transactions");
  assert.equal(navViewName({ id: "view-settings" }), "settings");
  assert.equal(navViewName({ id: "view-wizard" }), "");
  assert.equal(navViewName({ id: "view-login" }), "");
});

test("all view transitions use the helper loaded before the application", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");

  assert.ok(html.indexOf("/nav-view.js") < html.indexOf("/app.js"));
  assert.match(app, /function show\(viewId\) \{\s*activateViewState\(/);
  assert.match(app, /function enterApp\(\)[\s\S]*show\("#view-transactions"\)/);
  assert.match(
    app,
    /"#wiz-skip"\)\.addEventListener[\s\S]*show\("#view-settings"\)/,
  );
  assert.doesNotMatch(app, /classList\.toggle\("active", b === btn\)/);
});
