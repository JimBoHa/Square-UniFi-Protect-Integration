"use strict";

(function expose(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof globalThis === "object" ? globalThis : this, () => {
  const ROLES = new Set(["admin", "viewer"]);

  function loginAuditPage(payload) {
    const rows = payload && Array.isArray(payload.events) ? payload.events : [];
    const events = rows.filter((event) =>
      event &&
      Number.isSafeInteger(event.id) && event.id > 0 &&
      Number.isSafeInteger(event.user_id) && event.user_id > 0 &&
      typeof event.username === "string" && Boolean(event.username) &&
      ROLES.has(event.role) &&
      typeof event.client_ip === "string" && Boolean(event.client_ip) &&
      Number.isFinite(event.logged_in_at),
    ).map((event) => ({
      id: event.id,
      userId: event.user_id,
      username: event.username,
      role: event.role,
      clientIp: event.client_ip,
      loggedInAt: event.logged_in_at,
    }));
    const cursor = payload && payload.next_before_id;
    return {
      events,
      nextBeforeId: Number.isSafeInteger(cursor) && cursor > 0 ? cursor : null,
    };
  }

  return { loginAuditPage };
});
