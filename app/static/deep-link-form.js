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

if (typeof module !== "undefined") {
  module.exports = { applyDeepLinkSettings, deepLinkSettingsRequest };
}
