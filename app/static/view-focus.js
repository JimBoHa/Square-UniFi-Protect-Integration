"use strict";

function focusViewHeading(container) {
  if (!container || typeof container.querySelector !== "function") return false;
  const heading = container.querySelector("h1, h2, h3, h4, h5, h6");
  if (!heading) return false;

  const temporaryTabIndex = !heading.hasAttribute("tabindex");
  if (temporaryTabIndex) heading.setAttribute("tabindex", "-1");
  heading.focus();
  if (temporaryTabIndex) {
    heading.addEventListener(
      "blur",
      () => {
        if (heading.getAttribute("tabindex") === "-1") {
          heading.removeAttribute("tabindex");
        }
      },
      { once: true },
    );
  }
  return true;
}

if (typeof module !== "undefined") module.exports = { focusViewHeading };
