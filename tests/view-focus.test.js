"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { focusViewHeading } = require("../app/static/view-focus.js");

function heading(initialTabIndex = null) {
  const attributes = new Map();
  if (initialTabIndex !== null) attributes.set("tabindex", initialTabIndex);
  let blur = null;
  return {
    focusCount: 0,
    addEventListener(name, listener, options) {
      assert.equal(name, "blur");
      assert.deepEqual(options, { once: true });
      blur = listener;
    },
    blur() {
      if (blur) blur();
    },
    focus() {
      this.focusCount += 1;
    },
    getAttribute: (name) => attributes.get(name) || null,
    hasAttribute: (name) => attributes.has(name),
    removeAttribute: (name) => attributes.delete(name),
    setAttribute: (name, value) => attributes.set(name, value),
  };
}

test("view headings receive temporary programmatic focus semantics", () => {
  const visibleHeading = heading();
  const container = {
    querySelector(selector) {
      assert.equal(selector, "h1, h2, h3, h4, h5, h6");
      return visibleHeading;
    },
  };

  assert.equal(focusViewHeading(container), true);
  assert.equal(visibleHeading.focusCount, 1);
  assert.equal(visibleHeading.getAttribute("tabindex"), "-1");
  visibleHeading.blur();
  assert.equal(visibleHeading.hasAttribute("tabindex"), false);
});

test("existing heading tabindex is preserved and missing headings are ignored", () => {
  const alreadyFocusable = heading("0");
  assert.equal(
    focusViewHeading({ querySelector: () => alreadyFocusable }),
    true,
  );
  assert.equal(alreadyFocusable.getAttribute("tabindex"), "0");
  assert.equal(focusViewHeading({ querySelector: () => null }), false);
  assert.equal(focusViewHeading(null), false);
});

test("views focus after activation and wizard steps focus after being unhidden", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");

  assert.ok(html.indexOf("/view-focus.js") < html.indexOf("/app.js"));
  assert.match(
    app,
    /function show\(viewId, focusHeading = true\)[\s\S]*activateViewState\([\s\S]*if \(focusHeading\) focusViewHeading\(view\)/,
  );
  assert.match(app, /show\("#view-wizard", false\)/);
  const wizardStart = app.indexOf("function showWizardStep");
  const wizardEnd = app.indexOf("async function maybeStartWizard", wizardStart);
  const wizard = app.slice(wizardStart, wizardEnd);
  assert.ok(wizard.indexOf("el.hidden = !active") < wizard.indexOf("focusViewHeading(activeStep)"));
  assert.equal((app.match(/focusViewHeading\(/g) || []).length, 2);
});
