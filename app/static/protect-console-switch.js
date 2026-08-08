"use strict";

function cameraMappingSelectId(containerId, locationId, deviceId = "") {
  const target = JSON.stringify([String(locationId), String(deviceId || "")]);
  return `${containerId}-camera-${encodeURIComponent(target)}`;
}

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
    ? " Previous camera mappings and Protect evidence were cleared; the motion webhook was disabled. Please select POS cameras again and enable motion alerts."
    : "";
  return `Connected to UniFi Protect (${result.cameras} cameras found).${alarm}${reset}`;
}

function publishLatestSettingsLoad(loadGeneration, latestGeneration, publish) {
  if (loadGeneration !== latestGeneration) return false;
  publish();
  return true;
}

function settingsSnapshotsMatch({
  cameraGeneration,
  motionGeneration = null,
  locationRevision,
  mappingGeneration,
  mappingRevision,
}) {
  return (
    (cameraGeneration === null || cameraGeneration === mappingGeneration) &&
    (motionGeneration === null || motionGeneration === mappingGeneration) &&
    (locationRevision === null || locationRevision === mappingRevision)
  );
}

function publishCoherentSettingsLoad(
  loadGeneration,
  latestGeneration,
  snapshots,
  publish,
) {
  if (loadGeneration !== latestGeneration) return "discard";
  if (!settingsSnapshotsMatch(snapshots)) return "reload";
  publish();
  return "published";
}

function settingsSnapshotMismatchAction(retriesRemaining) {
  return retriesRemaining > 0 ? "retry" : "show-reload";
}

function clearProtectConsoleView(mappingRows, saveButton, previewWrap, previewImage) {
  mappingRows.textContent = "";
  saveButton.hidden = true;
  previewWrap.hidden = true;
  previewImage.removeAttribute("src");
}

if (typeof module !== "undefined") {
  module.exports = {
    cameraMappingSelectId,
    protectConnectionMessage,
    protectConsoleSwitchTokenRequest,
    publishLatestSettingsLoad,
    settingsSnapshotsMatch,
    publishCoherentSettingsLoad,
    settingsSnapshotMismatchAction,
    clearProtectConsoleView,
  };
}
