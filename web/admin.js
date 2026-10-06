"use strict";
import { parseRoute, deviceRoute, routeUrl } from "/admin/navigation.js";
const $ = (id) => document.getElementById(id);
let csrf = null,
  generation = 0,
  devices = [],
  settingsVersion = null,
  editing = null;
let quotaEnabled = false,
  approvalRequired = true,
  refreshId = 0;
const titles = {
  overview: "Overview",
  requests: "Access requests",
  devices: "Devices",
  settings: "Settings",
  activity: "Activity",
};
const settingKeys = [
  "default_rx_bps",
  "default_tx_bps",
  "quota_budget_bytes",
  "quota_headroom_bytes",
  "quota_overhead_pct",
  "quota_chunk_bytes",
  "alert_webhook_url",
];
function node(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (cls) el.className = cls;
  return el;
}
function bytes(n) {
  if (n === null || n === undefined) return "Not configured";
  let value = Number(n),
    unit = 0;
  const units = ["B", "kB", "MB", "GB", "TB"];
  while (value >= 1000 && unit < 4) {
    value /= 1000;
    unit++;
  }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value)} ${units[unit]}`;
}
function rate(n) {
  return n === null || n === undefined ? "Unlimited" : `${bytes(n)}/s`;
}
function date(s) {
  return s ? new Date(s).toLocaleString() : "Not observed";
}
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").className = error ? "error" : "";
}
function signedOut(message = "Sign in to manage your relay.") {
  generation++;
  csrf = null;
  devices = [];
  settingsVersion = null;
  $("dashboard").hidden = true;
  $("loginView").hidden = false;
  [
    "requestList",
    "deviceList",
    "auditList",
    "accessSummary",
    "requestsPagination",
    "devicesPagination",
    "activityPagination",
  ].forEach((id) => $(id).replaceChildren());
  [
    "health",
    "uptime",
    "connections",
    "approved",
    "period",
    "charged",
    "budget",
    "remaining",
    "cutoff",
    "budgetNote",
    "rx",
    "tx",
    "denied",
    "deniedDetail",
    "pendingPolicy",
    "networkSummary",
    "quotaSettingsNote",
  ].forEach((id) => ($(id).textContent = ""));
  $("requestCount").textContent = "0";
  $("budgetProgress").value = 0;
  $("settingsForm").reset();
  $("deviceForm").reset();
  $("editor").close();
  editing = null;
  notice("");
  $("loginMessage").textContent = message;
  $("tok").value = "";
}
async function api(path, options = {}) {
  const epoch = generation;
  const headers = {
    "Content-Type": "application/json",
    ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    ...options.headers,
  };
  const response = await fetch(`/admin/${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  const body = await response.json().catch(() => ({}));
  if (epoch !== generation) throw new Error("Session changed. Try again.");
  if (!response.ok) {
    if (response.status === 401 && path !== "login" && path !== "session")
      signedOut("Your session expired. Sign in again.");
    throw new Error(body.error || `Request failed (${response.status}).`);
  }
  return body;
}
function page(name) {
  document
    .querySelectorAll(".page")
    .forEach((el) => (el.hidden = el.id !== name));
  document.querySelectorAll("[data-page]").forEach((el) => {
    if (el.dataset.page === name) el.setAttribute("aria-current", "page");
    else el.removeAttribute("aria-current");
  });
  $("pageTitle").textContent = titles[name];
}
function restoreRoute() {
  const route = parseRoute(location.hash);
  page(route.page);
  $("deviceSearch").value = route.search;
  if (csrf) refresh().catch((e) => notice(e.message, true));
}
function showStatus(s) {
  $("health").textContent = s.db_ok ? "Healthy" : "Storage error";
  $("uptime").textContent =
    `Running for ${Math.floor(s.uptime_secs / 60)} minutes`;
  $("connections").textContent = s.live_connections;
  $("approved").textContent = s.approved_endpoints;
  $("rx").textContent = bytes(s.rx_bytes);
  $("tx").textContent = bytes(s.tx_bytes);
  $("denied").textContent =
    s.denied_unknown_total +
    s.denied_token_total +
    s.denied_quota_total +
    s.denied_busy_total + (s.network_limits?.rejected_total || 0);
  $("deniedDetail").textContent =
    `${s.denied_unknown_total} approval · ${s.denied_token_total} token · ${s.denied_quota_total} budget · ${s.denied_busy_total} capacity · ${s.network_limits?.rejected_total || 0} network`;
  const p = s.access_policy;
  const n = s.network_limits;
  $("networkSummary").textContent = n
    ? `Source IP: ${bytes(n.config.ip_rx_bps)}/s in · ${bytes(n.config.ip_tx_bps)}/s out. Global: ${bytes(n.config.global_rx_bps)}/s in · ${bytes(n.config.global_tx_bps)}/s out. IPv6 grouping: ${n.config.ipv6_prefix_enabled ? "/" + n.config.ipv6_prefix : "off"}. ${n.rejected_total} network refusals. Configure network safeguards in the server config and restart.`
    : "Network safeguards are not attached to this relay process.";
  approvalRequired = p.approval_required;
  titles.requests = approvalRequired ? "Access requests" : "Observed devices";
  $("observationLabel").textContent = titles.requests;
  $("requests").setAttribute("aria-label", titles.requests);
  $("requestsPagination").setAttribute("aria-label", `${titles.requests} pagination`);
  if (parseRoute(location.hash).page === "requests") $("pageTitle").textContent = titles.requests;
  $("observationIntro").textContent = approvalRequired
    ? "Review devices that tried to connect. Verify the endpoint fingerprint before granting access."
    : "Recent verified devices not yet saved. They can already use the relay; save a device to manage its policy.";
  $("accessSummary").replaceChildren(
    node(
      "span",
      p.token_required ? "Relay token required" : "No relay token required",
    ),
    node(
      "span",
      p.approval_required
        ? "Endpoint approval required"
        : "No endpoint approval required",
    ),
  );
  $("pendingPolicy").textContent = !p.approval_required
    ? "Endpoint approval is disabled. These are observations, not requests for access."
    : p.token_required
      ? "Only devices with a valid relay-access token appear here."
      : "Any device with a verified endpoint identity can request access. No relay token is required.";
  $("requestCount").textContent = approvalRequired ? s.pending_requests : s.observed_devices;
  const q = s.quota;
  quotaEnabled = q.implemented === true;
  $("quotaSettingsNote").textContent = quotaEnabled
    ? "Budget changes take effect immediately. Removing the budget disables its cutoff."
    : "The budget worker is disabled for this process. Configure a budget on the server and restart to enable enforcement; saving a budget here alone does not start it.";
  if (!quotaEnabled) {
    $("charged").textContent = "Not enabled";
    $("budget").textContent = "No monthly cutoff";
    $("period").textContent = "Disabled";
    $("budgetProgress").value = 0;
    $("remaining").textContent = "";
    $("cutoff").textContent = "";
    $("budgetNote").textContent =
      "Monthly budget enforcement is disabled for this process.";
    return;
  }
  $("period").textContent = `${q.period} · UTC`;
  $("charged").textContent = bytes(q.charged_bytes);
  $("budget").textContent =
    q.budget_bytes == null
      ? "No monthly cutoff"
      : `charged of ${bytes(q.budget_bytes)}`;
  $("budgetProgress").value = q.effective_cutoff_bytes
    ? Math.min(100, (q.charged_bytes / q.effective_cutoff_bytes) * 100)
    : 0;
  $("remaining").textContent = q.exhausted
    ? "Budget exhausted · relay access stopped"
    : q.effective_cutoff_bytes == null
      ? "No monthly cutoff"
      : `${bytes(q.available_bytes)} available before cutoff`;
  $("cutoff").textContent =
    q.effective_cutoff_bytes == null
      ? ""
      : `Effective cutoff: ${bytes(q.effective_cutoff_bytes)}`;
  $("budgetNote").textContent =
    `Charged usage includes relay payload, ${q.overhead_pct}% overhead allowance and outstanding reservations. It is not your hosting provider’s billable traffic. Headroom: ${bytes(q.headroom_bytes)}.`;
}
function button(text, handler, cls) {
  const b = node("button", text, cls);
  b.type = "button";
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await handler();
    } catch (e) {
      notice(e.message, true);
    } finally {
      b.disabled = false;
    }
  });
  return b;
}
function meta(items) {
  const div = node("div", undefined, "device-meta");
  items.forEach((item) => div.append(node("span", item)));
  return div;
}
function identityCard(title, id, badge, allowed) {
  const card = node("article", undefined, "device-card"),
    heading = node("div", undefined, "section-heading");
  heading.append(
    node("h2", title),
    node("span", badge, `badge ${allowed ? "allowed" : "blocked"}`),
  );
  card.append(heading, node("div", id, "endpoint-key"));
  return card;
}
function showDevices() {
  const rows = devices;
  $("deviceList").replaceChildren();
  if (!rows.length) {
    $("deviceList").append(
      node(
        "div",
        $("deviceSearch").value
          ? "No devices match your search."
          : "No saved devices yet. Approve an access request or add an endpoint ID.",
        "empty",
      ),
    );
    return;
  }
  rows.forEach((e) => {
    const card = identityCard(
        e.label || "Unnamed device",
        e.endpoint_id,
        e.approved ? "Allowed" : "Blocked",
        e.approved,
      ),
      o = e.observation;
    card.append(
      meta([
        `${e.live_connections} live connections`,
        `Receive: ${rate(e.effective_limits.rx_bps)}`,
        `Send: ${rate(e.effective_limits.tx_bps)}`,
        `Observed IP: ${o?.observed_ip || "Not observed"}`,
        `Last seen: ${date(o?.last_seen)}`,
      ]),
    );
    const actions = node("div", undefined, "actions");
    actions.append(button("Edit device", () => openEditor(e)));
    if (e.approved)
      actions.append(
        button(
          "Revoke access",
          async () => {
            if (
              !confirm(
                `Revoke access for ${e.label || "this device"}? Its existing relay connections will close.`,
              )
            )
              return;
            await api(`endpoints/${encodeURIComponent(e.endpoint_id)}/revoke`, {
              method: "POST",
            });
            await refresh();
            notice("Device access revoked.");
          },
          "danger",
        ),
      );
    else
      actions.append(
        button("Allow access", () => openEditor(e, true), "primary"),
      );
    card.append(actions);
    $("deviceList").append(card);
  });
}
function showRequests(rows) {
  $("requestList").replaceChildren();
  if (!rows.length) {
    $("requestList").append(
      node(
        "div",
        approvalRequired ? "No pending requests. Devices appear after an eligible connection attempt is refused for missing approval." : "No unsaved devices observed recently.",
        "empty",
      ),
    );
    return;
  }
  rows.forEach((r) => {
    const card = identityCard(
      "New device",
      r.endpoint_id,
      approvalRequired ? "Awaiting approval" : "Observed",
      false,
    );
    card.append(
      meta([
        `Observed IP: ${r.observed_ip || "Not available"}`,
        `${r.attempts} attempts`,
        `First seen: ${date(r.first_seen)}`,
        `Last seen: ${date(r.last_seen)}`,
      ]),
    );
    const actions = node("div", undefined, "actions");
    actions.append(
      button(
        approvalRequired ? "Review and approve" : "Save device",
        () =>
          openEditor(
            devices.find((e) => e.endpoint_id === r.endpoint_id) || {
              endpoint_id: r.endpoint_id,
            },
            true,
          ),
        "primary",
      ),
      button("Dismiss", async () => {
        await api(`pending/${encodeURIComponent(r.endpoint_id)}/dismiss`, {
          method: "POST",
        });
        await refresh();
        notice(approvalRequired ? "Request dismissed. A future attempt can create a new request." : "Observation dismissed. A future connection can appear again.");
      }),
    );
    card.append(actions);
    $("requestList").append(card);
  });
}
function showAudit(rows) {
  $("auditList").replaceChildren();
  if (!rows.length) {
    $("auditList").append(
      node("p", "No administrator actions recorded yet.", "help"),
    );
    return;
  }
  rows.forEach((e) => {
    const row = node("div", undefined, "audit-row"),
      when = node("time", date(e.at));
    when.dateTime = e.at;
    const detail = node("div", e.action.replaceAll("_", " "));
    if (e.target) detail.append(node("code", e.target));
    row.append(when, detail);
    $("auditList").append(row);
  });
}
function showPagination(name, p) {
  const nav = $(`${name}Pagination`);
  nav.replaceChildren();
  const route = parseRoute(location.hash);
  const summary = node(
    "span",
    p.total
      ? `${(p.page - 1) * p.page_size + 1}–${Math.min(p.page * p.page_size, p.total)} of ${p.total} · Page ${p.page} of ${p.total_pages}`
      : "0 entries",
  );
  nav.append(summary);
  if (p.total_pages > 1) {
    for (const [text, target, enabled] of [
      ["Previous", p.page - 1, p.page > 1],
      ["Next", p.page + 1, p.page < p.total_pages],
    ]) {
      const el = node(enabled ? "a" : "span", text);
      if (enabled) el.href = routeUrl(name, route.search, target);
      else el.setAttribute("aria-disabled", "true");
      nav.append(el);
    }
  }
  if (route.page === name && route.pageNumber !== p.page)
    history.replaceState(null, "", routeUrl(name, route.search, p.page));
}
async function refresh() {
  const requestId = ++refreshId;
  const route = parseRoute(location.hash);
  const pageFor = (name) => (name === route.page ? route.pageNumber : 1);
  $("refreshBtn").disabled = true;
  try {
    const [s, e, p, a] = await Promise.all([
      api("status"),
      api(
        `endpoints?page=${pageFor("devices")}&limit=20&q=${encodeURIComponent(route.search)}`,
      ),
      api(`pending?page=${pageFor("requests")}&limit=20`),
      api(`audit?page=${pageFor("activity")}&limit=20`),
    ]);
    if (requestId !== refreshId || !csrf) return;
    showStatus(s);
    devices = e.endpoints;
    showDevices();
    showRequests(p.requests);
    showAudit(a.events);
    showPagination("devices", e.pagination);
    showPagination("requests", p.pagination);
    showPagination("activity", a.pagination);
  } finally {
    if (requestId === refreshId) $("refreshBtn").disabled = false;
  }
}
async function loadSettings() {
  const s = await api("settings");
  settingsVersion = s.version;
  settingKeys.forEach(
    (key) => ($("settingsForm").elements[key].value = s.settings[key] ?? ""),
  );
}
function openEditor(e = null, approve = false) {
  editing = e;
  const form = $("deviceForm");
  form.reset();
  form.elements.endpoint_id.value = e?.endpoint_id || "";
  form.elements.endpoint_id.readOnly = !!e?.endpoint_id;
  form.elements.label.value = e?.label || "";
  form.elements.approved.checked = approve || e?.approved || false;
  form.elements.speed_policy.value = e?.speed_policy || "default";
  ["custom_rx_bps", "custom_tx_bps", "burst_bytes"].forEach(
    (k) => (form.elements[k].value = e?.[k] ?? ""),
  );
  $("customLimits").hidden = form.elements.speed_policy.value !== "custom";
  $("editorTitle").textContent = approve
    ? "Approve device"
    : e
      ? "Edit device"
      : "Add endpoint";
  $("editorMessage").textContent = "";
  $("editor").showModal();
}
function integer(input) {
  if (input.value.trim() === "") return null;
  const n = Number(input.value);
  if (!Number.isSafeInteger(n))
    throw new Error("Use a whole number within the supported range.");
  return n;
}
async function submit(form, task, messageTarget) {
  const b = form.querySelector('[type="submit"]');
  b.disabled = true;
  try {
    await task();
  } catch (e) {
    if (messageTarget) {
      messageTarget.textContent = e.message;
      messageTarget.className = "error";
    } else notice(e.message, true);
  } finally {
    b.disabled = false;
  }
}
$("loginForm").addEventListener("submit", (e) => {
  e.preventDefault();
  submit(
    e.currentTarget,
    async () => {
      const s = await api("login", {
        method: "POST",
        body: JSON.stringify({ token: $("tok").value }),
      });
      csrf = s.csrf;
      $("tok").value = "";
      $("loginView").hidden = true;
      $("dashboard").hidden = false;
      await Promise.all([refresh(), loadSettings()]);
    },
    $("loginMessage"),
  );
});
$("logoutBtn").addEventListener("click", async () => {
  try {
    await api("logout", { method: "POST" });
    signedOut("Signed out.");
  } catch (e) {
    notice(e.message, true);
  }
});
$("refreshBtn").addEventListener("click", () =>
  refresh()
    .then(() => notice("Data refreshed."))
    .catch((e) => notice(e.message, true)),
);
window.addEventListener("hashchange", restoreRoute);
$("deviceSearch").addEventListener("input", () => {
  history.replaceState(null, "", deviceRoute($("deviceSearch").value));
  refresh().catch((e) => notice(e.message, true));
});
restoreRoute();
$("addBtn").addEventListener("click", () => openEditor());
$("closeEditor").addEventListener("click", () => $("editor").close());
$("deviceForm").elements.speed_policy.addEventListener(
  "change",
  (e) => ($("customLimits").hidden = e.target.value !== "custom"),
);
$("deviceForm").addEventListener("submit", (e) => {
  e.preventDefault();
  submit(
    e.currentTarget,
    async () => {
      const f = e.currentTarget.elements,
        id = f.endpoint_id.value.trim(),
        custom = f.speed_policy.value === "custom";
      const body = {
        label: f.label.value,
        approved: f.approved.checked,
        speed_policy: f.speed_policy.value,
        custom_rx_bps: custom ? integer(f.custom_rx_bps) : null,
        custom_tx_bps: custom ? integer(f.custom_tx_bps) : null,
        burst_bytes: integer(f.burst_bytes),
      };
      if (editing?.revision) body.revision = editing.revision;
      await api(`endpoints/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(body),
      });
      $("editor").close();
      await refresh();
      notice(
        "Device saved. The client can reconnect using the same endpoint identity.",
      );
    },
    $("editorMessage"),
  );
});
$("settingsForm").addEventListener("submit", (e) => {
  e.preventDefault();
  submit(e.currentTarget, async () => {
    if (settingsVersion === null)
      throw new Error("Reload settings before saving.");
    const settings = {};
    settingKeys.forEach(
      (k) =>
        (settings[k] =
          k === "alert_webhook_url"
            ? e.currentTarget.elements[k].value.trim() || null
            : integer(e.currentTarget.elements[k])),
    );
    if (
      quotaEnabled &&
      settings.quota_budget_bytes === null &&
      !confirm("Remove the monthly budget? This disables the budget cutoff.")
    )
      return;
    const s = await api("settings", {
      method: "PATCH",
      body: JSON.stringify({ version: settingsVersion, settings }),
    });
    settingsVersion = s.version;
    await refresh();
    notice("Settings saved.");
  });
});
(async () => {
  try {
    const s = await api("session");
    csrf = s.csrf;
    $("loginView").hidden = true;
    $("dashboard").hidden = false;
    await Promise.all([refresh(), loadSettings()]);
  } catch (e) {
    if (!csrf) signedOut();
    else notice(e.message, true);
  }
})();
