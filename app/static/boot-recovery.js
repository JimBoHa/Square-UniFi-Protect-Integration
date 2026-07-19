"use strict";

function sessionExpiredError(message = "Please log in") {
  const error = new Error(message);
  error.sessionExpired = true;
  return error;
}

function isSessionExpiredError(error) {
  return Boolean(error && error.sessionExpired === true);
}

function bootFailureMessage(error) {
  const rawDetail = error && typeof error.message === "string"
    ? error.message.trim()
    : "";
  const detail = rawDetail || "Unexpected startup error";
  const sentence = /[.!?]$/.test(detail) ? detail : `${detail}.`;
  return `Could not load the application: ${sentence} ` +
    "Check the server connection and logs, then try again.";
}

if (typeof module !== "undefined") {
  module.exports = {
    bootFailureMessage,
    isSessionExpiredError,
    sessionExpiredError,
  };
}
