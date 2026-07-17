/* Square × UniFi Protect frontend. All dynamic text is set via textContent —
   server data is never interpreted as markup, which rules out DOM XSS. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const TRANSACTION_REFRESH_MS = 15000;

let transactionRefreshTimer = null;
let transactionLoadInFlight = false;
let lastTransactionPayload = null;

function show(viewId) {
  for (const sec of document.querySelectorAll("main > section")) sec.hidden = true;
  $(viewId).hidden = false;
}

function message(text, kind) {
  const el = $("#message");
  el.textContent = text || "";
  el.className = kind || "";
}

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...options,
  });
  if (resp.status === 401 && path !== "/api/login") {
    show("#view-login");
    $("#nav").hidden = true;
    throw new Error("Please log in");
  }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.detail || `Request failed (${resp.status})`);
  return data;
}

// ---------------------------------------------------------------- boot

async function boot() {
  const status = await api("/api/status");
  if (!status.setup_complete) {
    show("#view-setup");
    return;
  }
  // Probe an authed endpoint to see if we already have a session.
  try {
    await api("/api/camera-mapping");
    enterApp();
  } catch {
    /* api() already routed to login view */
  }
}

function enterApp() {
  $("#nav").hidden = false;
  show("#view-transactions");
  loadTransactions();
  loadSettingsView();
  startTransactionRefresh();
}

// ---------------------------------------------------------------- auth

$("#setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/setup", {
      method: "POST",
      body: JSON.stringify({ password: $("#setup-password").value }),
    });
    message("Admin password created. Please log in.", "ok");
    show("#view-login");
  } catch (err) {
    message(err.message, "error");
  }
});

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: $("#login-password").value }),
    });
    $("#login-password").value = "";
    message("", "");
    enterApp();
  } catch (err) {
    message(err.message, "error");
  }
});

$("#logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch { /* session gone */ }
  stopTransactionRefresh();
  $("#nav").hidden = true;
  show("#view-login");
});

for (const btn of document.querySelectorAll("nav button[data-view]")) {
  btn.addEventListener("click", () => {
    for (const b of document.querySelectorAll("nav button[data-view]"))
      b.classList.toggle("active", b === btn);
    show(`#view-${btn.dataset.view}`);
    if (btn.dataset.view === "transactions") loadTransactions();
    if (btn.dataset.view === "settings") loadSettingsView();
  });
}

// ---------------------------------------------------------------- settings

$("#protect-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const result = await api("/api/settings/protect", {
      method: "PUT",
      body: JSON.stringify({
        host: $("#protect-host").value.trim(),
        username: $("#protect-username").value.trim(),
        password: $("#protect-password").value,
        verify_ssl: $("#protect-verify-ssl").checked,
        api_key: $("#protect-api-key").value.trim(),
        alarm_trigger_id: $("#protect-alarm-trigger-id").value.trim(),
      }),
    });
    $("#protect-password").value = "";
    $("#protect-api-key").value = "";
    const alarm = result.alarm_configured ? " Alarm trigger enabled." : "";
    message(`Connected to UniFi Protect (${result.cameras} cameras found).${alarm}`, "ok");
    loadSettingsView();
  } catch (err) {
    message(err.message, "error");
  }
});

$("#protect-disable-alarm").addEventListener("click", async () => {
  try {
    await api("/api/settings/protect/alarm", { method: "DELETE" });
    $("#protect-api-key").value = "";
    $("#protect-alarm-trigger-id").value = "";
    message("Protect alarm trigger disabled.", "ok");
  } catch (err) {
    message(err.message, "error");
  }
});

$("#square-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const result = await api("/api/settings/square", {
      method: "PUT",
      body: JSON.stringify({
        access_token: $("#square-token").value.trim(),
        environment: $("#square-env").value,
        webhook_signature_key: $("#square-webhook-key").value.trim(),
        webhook_url: $("#square-webhook-url").value.trim(),
        clear_webhook: $("#square-clear-webhook").checked,
      }),
    });
    $("#square-token").value = "";
    $("#square-webhook-key").value = "";
    message(`Connected to Square (${result.locations.length} locations).`, "ok");
    loadSettingsView();
  } catch (err) {
    message(err.message, "error");
  }
});

async function loadSettingsView() {
  const rows = $("#mapping-rows");
  rows.textContent = "";
  let cameras = [], locations = [], mappings = [], devices = [];
  try { cameras = await api("/api/cameras"); } catch { /* Protect not configured yet */ }
  try { locations = await api("/api/locations"); } catch { /* Square not configured yet */ }
  try { devices = await api("/api/pos-devices"); } catch { /* No observed devices yet */ }
  try { mappings = await api("/api/camera-mapping"); } catch { return; }

  if (!cameras.length || !locations.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Connect both UniFi Protect and Square above to choose the POS camera.";
    rows.appendChild(p);
    $("#save-mapping").hidden = true;
    return;
  }
  $("#save-mapping").hidden = false;
  const mappingKey = (locationId, deviceId = "") =>
    JSON.stringify([locationId, deviceId || ""]);
  const current = new Map(mappings.map((m) => [
    mappingKey(m.location_id, m.device_id),
    m.camera_id,
  ]));
  const devicesByLocation = new Map();
  for (const device of devices) {
    if (!devicesByLocation.has(device.location_id))
      devicesByLocation.set(device.location_id, []);
    devicesByLocation.get(device.location_id).push(device);
  }

  for (const loc of locations) {
    const observed = devicesByLocation.get(loc.id) || [];
    const targets = [
      { device_id: "", device_name: "" },
      ...observed,
    ];
    for (const target of targets) {
      const row = document.createElement("div");
      row.className = "mapping-row";
      const label = document.createElement("span");
      label.className = "loc";
      const locationName = loc.name || loc.id;
      if (target.device_id) {
        label.textContent = `${locationName} — ${target.device_name || target.device_id}`;
      } else if (observed.length) {
        label.textContent = `${locationName} — Other devices (fallback)`;
      } else {
        label.textContent = locationName;
      }
      const select = document.createElement("select");
      select.dataset.locationId = loc.id;
      select.dataset.deviceId = target.device_id || "";
      select.dataset.deviceName = target.device_name || "";
      const none = document.createElement("option");
      none.value = "";
      none.textContent = "— no camera —";
      select.appendChild(none);
      for (const cam of cameras) {
        const opt = document.createElement("option");
        opt.value = cam.id;
        opt.textContent = cam.name;
        if (current.get(mappingKey(loc.id, target.device_id)) === cam.id)
          opt.selected = true;
        select.appendChild(opt);
      }
      select.addEventListener("change", () => previewCamera(select.value));
      row.appendChild(label);
      row.appendChild(select);
      rows.appendChild(row);
    }
  }
}

function previewCamera(cameraId) {
  const wrap = $("#camera-preview-wrap");
  if (!cameraId) { wrap.hidden = true; return; }
  wrap.hidden = false;
  $("#camera-preview").src = `/api/camera-preview/${encodeURIComponent(cameraId)}?t=${Date.now()}`;
}

$("#save-mapping").addEventListener("click", async () => {
  const mappings = [];
  for (const select of document.querySelectorAll("#mapping-rows select")) {
    if (!select.value) continue;
    mappings.push({
      location_id: select.dataset.locationId,
      device_id: select.dataset.deviceId || "",
      device_name: select.dataset.deviceName || "",
      camera_id: select.value,
      camera_name: select.options[select.selectedIndex].textContent,
    });
  }
  try {
    await api("/api/camera-mapping", { method: "PUT", body: JSON.stringify({ mappings }) });
    message("Camera selection saved.", "ok");
  } catch (err) {
    message(err.message, "error");
  }
});

// ---------------------------------------------------------------- transactions

function transactionViewIsVisible() {
  return document.visibilityState === "visible" &&
    !$("#nav").hidden && !$("#view-transactions").hidden;
}

function refreshTransactionsIfVisible() {
  if (transactionViewIsVisible()) loadTransactions();
}

function startTransactionRefresh() {
  if (transactionRefreshTimer !== null) return;
  transactionRefreshTimer = window.setInterval(
    refreshTransactionsIfVisible,
    TRANSACTION_REFRESH_MS,
  );
}

function stopTransactionRefresh() {
  if (transactionRefreshTimer === null) return;
  window.clearInterval(transactionRefreshTimer);
  transactionRefreshTimer = null;
}

document.addEventListener("visibilitychange", refreshTransactionsIfVisible);

async function loadTransactions() {
  if (transactionLoadInFlight) return;
  transactionLoadInFlight = true;
  let txns;
  try {
    txns = await api("/api/transactions?limit=100");
  } catch (err) {
    message(err.message, "error");
    return;
  } finally {
    transactionLoadInFlight = false;
  }
  $("#txn-last-updated").textContent =
    `Last updated ${new Date().toLocaleTimeString()}`;
  const payload = JSON.stringify(txns);
  if (payload === lastTransactionPayload) return;
  lastTransactionPayload = payload;
  const list = $("#txn-list");
  list.textContent = "";
  if (!txns.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No transactions yet. Connect Square, then press “Sync now”.";
    list.appendChild(p);
    return;
  }
  for (const txn of txns) {
    const row = document.createElement("div");
    row.className = "txn";

    let thumb;
    if (txn.thumbnail_url) {
      thumb = document.createElement("img");
      thumb.className = "thumb";
      thumb.src = txn.thumbnail_url;
      thumb.alt = "POS camera at time of transaction";
      thumb.title = "Open UniFi Protect timeline at this moment";
      if (txn.deep_link) {
        thumb.addEventListener("click", () => {
          window.open(txn.deep_link, "_blank", "noopener");
        });
      }
    } else {
      thumb = document.createElement("div");
      thumb.className = "thumb placeholder";
      thumb.textContent = "no footage";
    }

    const amount = document.createElement("div");
    amount.className = "amount";
    amount.textContent = formatAmount(txn.amount, txn.currency);

    const meta = document.createElement("div");
    const when = document.createElement("div");
    when.className = "meta";
    when.textContent = new Date(txn.ts_ms).toLocaleString();
    const card = document.createElement("div");
    card.className = "meta";
    card.textContent = txn.card_last4 ? `Card •••• ${txn.card_last4}` : "";
    const status = document.createElement("div");
    status.className = "status";
    status.textContent = txn.status;
    meta.appendChild(when);
    meta.appendChild(card);
    meta.appendChild(status);

    row.appendChild(thumb);
    row.appendChild(amount);
    row.appendChild(meta);
    list.appendChild(row);
  }
}

$("#sync-now").addEventListener("click", async () => {
  message("Syncing…", "");
  try {
    const result = await api("/api/sync", { method: "POST" });
    message(`Synced ${result.ingested} transactions.`, "ok");
    loadTransactions();
  } catch (err) {
    message(err.message, "error");
  }
});

boot();
