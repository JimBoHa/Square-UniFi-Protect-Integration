"use strict";

function deepLinkSettingsRequest(input) {
  return { template: input.value.trim() };
}

function applyDeepLinkSettings(input, status, settings) {
  const template = typeof settings.template === "string" ? settings.template : "";
  const defaultTemplate = typeof settings.default_template === "string"
    ? settings.default_template
    : "";
  input.value = template;
  input.placeholder = defaultTemplate;
  status.textContent = template
    ? "Using a custom Protect timeline-link template."
    : `Using built-in default: ${defaultTemplate}`;
}

function createLatestDeepLinkSettingsLoader(fetchSettings, renderSettings) {
  let generation = 0;
  const load = async () => {
    const currentGeneration = ++generation;
    let settings;
    try {
      settings = await fetchSettings();
    } catch {
      return;
    }
    if (currentGeneration === generation) renderSettings(settings);
  };
  load.invalidate = () => { generation += 1; };
  return load;
}

if (typeof module !== "undefined") {
  module.exports = {
    applyDeepLinkSettings,
    createLatestDeepLinkSettingsLoader,
    deepLinkSettingsRequest,
  };
}
