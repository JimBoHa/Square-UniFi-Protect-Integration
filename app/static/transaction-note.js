"use strict";

(function expose(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof globalThis === "object" ? globalThis : this, () => {
  const MAX_TRANSACTION_NOTE_LENGTH = 2000;

  function transactionNoteState(transaction) {
    const note = transaction && typeof transaction.note === "string"
      ? transaction.note
      : "";
    const revision = transaction && Number.isSafeInteger(transaction.note_revision)
      && transaction.note_revision >= 0
      ? transaction.note_revision
      : 0;
    return {
      note: note.slice(0, MAX_TRANSACTION_NOTE_LENGTH),
      revision,
    };
  }

  function transactionNoteUpdate(note, revision) {
    const value = typeof note === "string" ? note : "";
    if (value.length > MAX_TRANSACTION_NOTE_LENGTH)
      throw new Error("Clip notes are limited to 2000 characters.");
    if ([...value].some((character) => {
      const code = character.codePointAt(0);
      return (code < 32 && !"\r\n\t".includes(character)) || code === 127;
    })) throw new Error("Clip note contains an unsupported control character.");
    if (!Number.isSafeInteger(revision) || revision < 0)
      throw new Error("Reload this transaction before saving its note.");
    return { note: value, revision };
  }

  return {
    MAX_TRANSACTION_NOTE_LENGTH,
    transactionNoteState,
    transactionNoteUpdate,
  };
});
