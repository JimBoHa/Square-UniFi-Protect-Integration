"use strict";

function createLatestSettingsLoader(loadSettings, renderSettings) {
  let latestRequest = 0;
  return async function loadLatestSettings() {
    const request = ++latestRequest;
    const settings = await loadSettings();
    if (request !== latestRequest) return false;
    renderSettings(settings);
    return true;
  };
}

if (typeof module !== "undefined") module.exports = { createLatestSettingsLoader };
