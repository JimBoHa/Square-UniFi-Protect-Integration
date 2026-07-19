"use strict";

(function initBootstrapForm(root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) Object.assign(root, api);
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  function isLoopbackBrowserHostname(hostname) {
    let normalized = String(hostname || "").trim().toLowerCase();
    if (normalized.startsWith("[") && normalized.endsWith("]")) {
      normalized = normalized.slice(1, -1);
    }
    normalized = normalized.replace(/\.$/, "");
    if (normalized === "localhost" || normalized === "::1") return true;
    if (normalized.startsWith("::ffff:")) {
      normalized = normalized.slice("::ffff:".length);
    }
    const octets = normalized.split(".");
    return (
      octets.length === 4 &&
      octets[0] === "127" &&
      octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
    );
  }

  function bootstrapTransportError(location) {
    if (location.protocol === "https:") return "";
    if (!isLoopbackBrowserHostname(location.hostname)) {
      return [
        "Remote first-run setup requires HTTPS.",
        "Enable SPI_TLS=1 on the server and reopen this page with https://.",
      ].join(" ");
    }
    return "";
  }

  return { bootstrapTransportError, isLoopbackBrowserHostname };
});
