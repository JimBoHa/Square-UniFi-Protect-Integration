"use strict";

function protectConsoleSwitchTokenRequest(confirmationCheckbox, settings) {
  if (!confirmationCheckbox.checked) return null;
  return {
    host: settings.host,
    username: settings.username,
    password: settings.password,
    verify_ssl: settings.verify_ssl,
  };
}

function protectConnectionMessage(result) {
  const alarm = result.alarm_configured ? " Alarm trigger enabled." : "";
  const reset = result.console_switched
    ? " Previous camera mappings and Protect evidence were cleared; select POS cameras again."
    : "";
  return `Connected to UniFi Protect (${result.cameras} cameras found).${alarm}${reset}`;
}

function publishLatestSettingsLoad(loadGeneration, latestGeneration, publish) {
  if (loadGeneration !== latestGeneration) return false;
  publish();
  return true;
}

function clearProtectConsoleView(mappingRows, saveButton, previewWrap, previewImage) {
  mappingRows.textContent = "";
  saveButton.hidden = true;
  previewWrap.hidden = true;
  previewImage.removeAttribute("src");
}

if (typeof module !== "undefined") {
  module.exports = {
    protectConnectionMessage,
    protectConsoleSwitchTokenRequest,
    publishLatestSettingsLoad,
    clearProtectConsoleView,
  };
}
