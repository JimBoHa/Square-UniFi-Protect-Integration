"use strict";

(function expose(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof globalThis === "object" ? globalThis : this, () => {
  const ROLES = new Set(["admin", "viewer"]);

  function sessionUser(payload) {
    const user = payload && typeof payload === "object" && payload.user
      ? payload.user
      : payload;
    if (
      !user ||
      typeof user !== "object" ||
      typeof user.username !== "string" ||
      !user.username ||
      !ROLES.has(user.role)
    ) return null;
    return { username: user.username, role: user.role };
  }

  function isAdmin(user) {
    return Boolean(user && user.role === "admin");
  }

  function roleLabel(user) {
    if (!user) return "";
    return `${user.username} · ${isAdmin(user) ? "Administrator" : "View only"}`;
  }

  function applyRoleInterface(user, adminOnlyElements, identityElement) {
    const admin = isAdmin(user);
    for (const element of adminOnlyElements || []) element.hidden = !admin;
    if (identityElement) identityElement.textContent = roleLabel(user);
    return admin;
  }

  return { applyRoleInterface, isAdmin, roleLabel, sessionUser };
});
