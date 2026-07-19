"use strict";

function navViewName(section) {
  const name = section && typeof section.id === "string"
    ? section.id.replace(/^view-/, "")
    : "";
  return name === "transactions" || name === "settings" ? name : "";
}

function activateViewState(sections, target, navButtons) {
  for (const section of sections) section.hidden = section !== target;
  target.hidden = false;

  const activeView = navViewName(target);
  for (const button of navButtons) {
    const active = button.dataset.view === activeView;
    button.classList.toggle("active", active);
    if (active) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  }
  return activeView;
}

if (typeof module !== "undefined") {
  module.exports = { activateViewState, navViewName };
}
