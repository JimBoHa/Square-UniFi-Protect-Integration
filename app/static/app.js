/* Square × UniFi Protect frontend. All dynamic text is set via textContent —
   server data is never interpreted as markup, which rules out DOM XSS. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const TRANSACTION_REFRESH_MS = 15000;
const TRANSACTION_PAGE_SIZE = 100;

let transactionRefreshTimer = null;
let transactionLoadInFlight = false;
let transactionPendingOffset = null;
let transactionOffset = 0;
let transactionHasNext = false;
let transactionPageCount = 0;
let transactionSnapshot = null;
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
  const { includeResponse = false, ...requestOptions } = options;
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...requestOptions,
  });
  const data = await resp.json().catch(() => ({}));
  // Only an expired/missing app session should bounce to the login view.
  // Settings endpoints also return 401 when UniFi Protect or Square reject
  // the submitted credentials; those must surface as inline errors instead
  // of asking the operator to log out and back in.
  const sessionExpired =
    resp.status === 401 &&
    path !== "/api/login" &&
    data.detail === "Authentication required";
  if (sessionExpired) {
    show("#view-login");
    $("#nav").hidden = true;
    throw new Error("Please log in");
  }
  if (!resp.ok) {
    const error = new Error(data.detail || `Request failed (${resp.status})`);
    error.status = resp.status;
    throw error;
  }
  return includeResponse ? { data, response: resp } : data;
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
  loadTransactions({ reset: true });
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

const loadDeepLinkSettings = createLatestDeepLinkSettingsLoader(
  () => api("/api/settings/deep-link"),
  (settings) => applyDeepLinkSettings(
    $("#deep-link-template"),
    $("#deep-link-status"),
    settings,
  ),
);

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

$("#deep-link-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const result = await api("/api/settings/deep-link", {
      method: "PUT",
      body: JSON.stringify(deepLinkSettingsRequest($("#deep-link-template"))),
    });
    loadDeepLinkSettings.invalidate();
    applyDeepLinkSettings(
      $("#deep-link-template"),
      $("#deep-link-status"),
      result,
    );
    message(
      result.template
        ? "Custom Protect timeline link saved."
        : "Protect timeline link restored to the built-in default.",
      "ok",
    );
  } catch (err) {
    message(err.message, "error");
  }
});

$("#square-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const webhookFields = squareWebhookRequestFields(
      $("#square-webhook-key"),
      $("#square-webhook-url"),
      $("#square-clear-webhook"),
    );
    const result = await api("/api/settings/square", {
      method: "PUT",
      body: JSON.stringify({
        access_token: $("#square-token").value.trim(),
        environment: $("#square-env").value,
        ...webhookFields,
      }),
    });
    $("#square-token").value = "";
    resetSquareWebhookFields(
      $("#square-webhook-key"),
      $("#square-webhook-url"),
      $("#square-clear-webhook"),
    );
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
  loadDeepLinkSettings();
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

function transactionRefreshAllowed() {
  // Refresh whenever the operator is logged in and the browser tab is
  // visible — including while the Settings section is open — so the feed is
  // always current the moment they switch back. Paging into history
  // (offset > 0) still pauses refresh so rows cannot shift underfoot.
  return document.visibilityState === "visible" &&
    !$("#nav").hidden && transactionOffset === 0;
}

function refreshTransactionsIfVisible() {
  // Offset pages would shift when new sales arrive. Keep older pages stable;
  // returning to the newest page resumes the normal live refresh.
  if (transactionRefreshAllowed()) void loadTransactions({ reset: true });
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

function updateTransactionPagination(loading = false) {
  $("#txn-prev").disabled = loading || transactionOffset === 0;
  $("#txn-next").disabled = loading || !transactionHasNext;
  const status = $("#txn-page-status");
  if (loading) {
    status.textContent = "Loading transaction page…";
  } else if (!transactionPageCount) {
    status.textContent = "No transactions to show";
  } else {
    const first = transactionOffset + 1;
    const last = transactionOffset + transactionPageCount;
    const oldest = transactionHasNext ? "" : " · oldest reached";
    const paused = transactionOffset > 0 ? " · auto-refresh paused" : "";
    status.textContent = `Showing transactions ${first}–${last}${oldest}${paused}`;
  }
}

function renderTransactions(txns) {
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
      const image = document.createElement("img");
      image.className = "thumb";
      image.src = txn.thumbnail_url;
      image.alt = "POS camera at time of transaction";
      if (txn.deep_link) {
        const link = document.createElement("a");
        link.className = "thumbnail-link";
        link.href = txn.deep_link;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.setAttribute(
          "aria-label",
          `Open UniFi Protect footage for transaction at ${new Date(txn.ts_ms).toLocaleString()}`,
        );
        link.title = "Open UniFi Protect timeline at this moment";
        link.appendChild(image);
        thumb = link;
      } else {
        thumb = image;
      }
    } else {
      thumb = document.createElement("div");
      thumb.className = "thumb placeholder";
      const thumbnailLabels = {
        unmapped: "camera not mapped",
        queued: "footage queued",
        retrying: "capture retrying",
      };
      thumb.textContent = thumbnailLabels[txn.thumbnail_status] || "no footage";
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

async function loadTransactions({ reset = false, offset = transactionOffset } = {}) {
  const requestedOffset = reset ? 0 : Math.max(0, offset);
  if (transactionLoadInFlight) {
    // Coalesce refreshes but retain the latest requested page. In particular,
    // a sync reset cannot be lost behind an older in-flight page request.
    transactionPendingOffset = requestedOffset;
    return;
  }
  transactionLoadInFlight = true;
  updateTransactionPagination(true);
  let page = null;
  let pageSnapshot = null;
  try {
    const snapshotParam = requestedOffset > 0 && transactionSnapshot !== null
      ? `&snapshot=${encodeURIComponent(transactionSnapshot)}`
      : "";
    const result = await api(
      `/api/transactions?limit=${TRANSACTION_PAGE_SIZE + 1}` +
        `&offset=${requestedOffset}${snapshotParam}`,
      { includeResponse: true },
    );
    page = result.data;
    pageSnapshot = result.response.headers.get("x-transaction-snapshot");
  } catch (err) {
    if (err.status === 409 && requestedOffset > 0) {
      // Durable ordering snapshots are bounded. An expired page restarts at
      // the newest chronological view instead of mixing two generations.
      transactionSnapshot = null;
      transactionPendingOffset = 0;
      message("Transaction page refreshed to the newest results.", "");
    } else {
      message(err.message, "error");
    }
  } finally {
    transactionLoadInFlight = false;
  }

  // Ignore a response when a newer page/reset request arrived while it was
  // loading. The queued request below becomes the only rendered result.
  if (page && transactionPendingOffset === null) {
    const txns = page.slice(0, TRANSACTION_PAGE_SIZE);
    if (!txns.length && requestedOffset > 0) {
      transactionPendingOffset = Math.max(0, requestedOffset - TRANSACTION_PAGE_SIZE);
    } else {
      transactionOffset = requestedOffset;
      transactionSnapshot = pageSnapshot;
      transactionHasNext = page.length > TRANSACTION_PAGE_SIZE;
      transactionPageCount = txns.length;
      $("#txn-last-updated").textContent =
        `Last updated ${new Date().toLocaleTimeString()}`;
      const payload = JSON.stringify({
        offset: transactionOffset,
        snapshot: transactionSnapshot,
        hasNext: transactionHasNext,
        transactions: txns,
      });
      if (payload !== lastTransactionPayload) {
        lastTransactionPayload = payload;
        renderTransactions(txns);
      }
    }
  }
  updateTransactionPagination(false);

  if (transactionPendingOffset !== null) {
    const pendingOffset = transactionPendingOffset;
    transactionPendingOffset = null;
    void loadTransactions({ offset: pendingOffset });
  }
}

$("#txn-prev").addEventListener("click", () => {
  if (transactionLoadInFlight || transactionOffset === 0) return;
  void loadTransactions({
    offset: Math.max(0, transactionOffset - TRANSACTION_PAGE_SIZE),
  });
});

$("#txn-next").addEventListener("click", () => {
  if (transactionLoadInFlight || !transactionHasNext) return;
  void loadTransactions({ offset: transactionOffset + TRANSACTION_PAGE_SIZE });
});

$("#sync-now").addEventListener("click", async () => {
  message("Syncing…", "");
  try {
    const result = await api("/api/sync", { method: "POST" });
    message(`Synced ${result.ingested} transactions.`, "ok");
    await loadTransactions({ reset: true });
  } catch (err) {
    message(err.message, "error");
  }
});

boot();
