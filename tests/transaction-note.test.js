"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  MAX_TRANSACTION_NOTE_LENGTH,
  transactionNoteState,
  transactionNoteUpdate,
} = require("../app/static/transaction-note.js");

test("transaction note state is bounded and revision-aware", () => {
  assert.deepEqual(
    transactionNoteState({ note: "review", note_revision: 4 }),
    { note: "review", revision: 4 },
  );
  assert.deepEqual(transactionNoteState({ note: null, note_revision: -1 }), {
    note: "",
    revision: 0,
  });
  assert.equal(
    transactionNoteState({ note: "x".repeat(2100), note_revision: 0 }).note.length,
    MAX_TRANSACTION_NOTE_LENGTH,
  );
});

test("note update payload preserves formatting and rejects stale shapes", () => {
  assert.deepEqual(transactionNoteUpdate("line one\nline two", 3), {
    note: "line one\nline two",
    revision: 3,
  });
  assert.throws(
    () => transactionNoteUpdate("x".repeat(2001), 0),
    /limited to 2000/,
  );
  assert.throws(() => transactionNoteUpdate("note", -1), /Reload/);
  assert.throws(() => transactionNoteUpdate("bad\0note", 0), /control character/);
});

test("transaction cards show read-only notes and admin-only text editors", () => {
  const staticDir = path.join(__dirname, "../app/static");
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");
  const css = fs.readFileSync(path.join(staticDir, "style.css"), "utf8");

  assert.ok(html.indexOf("/transaction-note.js") < html.indexOf("/app.js"));
  assert.match(html, /placeholder="Transaction ID, note, card last 4/);
  assert.match(app, /if \(!isAdmin\(currentUser\)\)/);
  assert.match(app, /text\.textContent = value/);
  assert.match(app, /textarea\.value = state\.note/);
  assert.match(app, /document\.createElement\("details"\)/);
  assert.match(app, /encodeURIComponent\(txn\.id\)\}\/note/);
  assert.match(app, /transactionSnapshot = null/);
  assert.doesNotMatch(app, /innerHTML\s*=/);
  assert.match(css, /\.clip-note p \{[^}]*white-space: pre-wrap/);
});
