"use strict";

function frameOffsetText(offsetMs) {
  if (offsetMs === null || offsetMs === undefined || offsetMs === "") return "";
  const value = Number(offsetMs);
  if (!Number.isFinite(value)) return "";
  const sign = value > 0 ? "+" : value < 0 ? "−" : "";
  return `UniFi frame ${sign}${(Math.abs(value) / 1000).toFixed(3)} s`;
}

function frameOffsetTitle(offsetMs) {
  const value = Number(offsetMs);
  if (!Number.isFinite(value)) return "";
  const relation = value < 0 ? "before" : value > 0 ? "after" : "at";
  return `Burned-in UniFi timestamp is ${(Math.abs(value) / 1000).toFixed(3)} seconds ${relation} the Square timestamp (whole-second frame precision).`;
}

if (typeof module !== "undefined") {
  module.exports = { frameOffsetText, frameOffsetTitle };
}
