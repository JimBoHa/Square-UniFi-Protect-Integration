"use strict";

(function expose(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof globalThis === "object" ? globalThis : this, () => {
  const ROLE_LABELS = { admin: "Administrator", viewer: "View only" };

  function passwordPairError(password, confirmation) {
    if (typeof password !== "string" || password.length < 8)
      return "Password must be at least 8 characters.";
    if (password.length > 256)
      return "Password must be no more than 256 characters.";
    if (password !== confirmation) return "Passwords do not match.";
    return "";
  }

  function accountRoleLabel(role) {
    return ROLE_LABELS[role] || "Unknown role";
  }

  function userAccounts(payload) {
    const users = payload && Array.isArray(payload.users) ? payload.users : [];
    return users.filter((user) =>
      user &&
      Number.isSafeInteger(user.id) && user.id > 0 &&
      typeof user.username === "string" && Boolean(user.username) &&
      Object.prototype.hasOwnProperty.call(ROLE_LABELS, user.role) &&
      typeof user.enabled === "boolean" &&
      Number.isFinite(user.created_at),
    ).map((user) => ({
      id: user.id,
      username: user.username,
      role: user.role,
      enabled: user.enabled,
      createdAt: user.created_at,
      current: user.current === true,
    }));
  }

  return { accountRoleLabel, passwordPairError, userAccounts };
});
