"use strict";

function createLatestAsyncRenderer(loadValue, renderValue) {
  let latestRequest = 0;
  return async function loadLatestValue() {
    const request = ++latestRequest;
    const value = await loadValue();
    if (request !== latestRequest) return false;
    renderValue(value);
    return true;
  };
}

function createLatestSettingsLoader(loadSettings, renderSettings) {
  return createLatestAsyncRenderer(loadSettings, renderSettings);
}

function createLatestStatusRefresher(loadStatus, renderStatus) {
  return createLatestAsyncRenderer(loadStatus, renderStatus);
}

if (typeof module !== "undefined") {
  module.exports = {
    createLatestSettingsLoader,
    createLatestStatusRefresher,
  };
}
