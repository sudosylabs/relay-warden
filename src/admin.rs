//! Private admin API + minimal UI (Gate B).
//!
//! Loopback-only listener (separate from relay port). Auth: Bearer token
//! (from a restricted secret file) or short-lived session cookie + CSRF.
//! No default password; no secrets in logs/audit/URLs.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Router,
};
use base64::Engine as _;
use subtle::ConstantTimeEq;

use crate::{
    limiter::LimiterMap,
    policy::{escape_html, EndpointUpsert, PolicyManager},
    quota::QuotaManager,
    service::App,
};

const SESSION_COOKIE: &str = "warden_session";
const SESSION_TTL: Duration = Duration::from_secs(3600);
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_ATTEMPTS: usize = 10;

#[derive(Debug)]
struct Session {
    csrf: String,
    expires: Instant,
}

#[derive(Debug, Clone)]
pub struct AdminState {
    app: Arc<App>,
    token: Vec<u8>,
    sessions: Arc<tokio::sync::Mutex<HashMap<String, Session>>>,
    login_attempts: Arc<tokio::sync::Mutex<HashMap<String, (usize, Instant)>>>,
    started: Instant,
}

impl AdminState {
    pub fn new(
        policy: Arc<PolicyManager>,
        limiter: Arc<LimiterMap>,
        quota: Option<Arc<QuotaManager>>,
        token: Vec<u8>,
    ) -> Self {
        let store = policy.store().clone();
        Self {
            app: Arc::new(App::new(policy, limiter, quota, store)),
            token,
            sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            login_attempts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            started: Instant::now(),
        }
    }
}

fn random_token() -> String {
    let b: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bearer_valid(provided: &str, expected: &[u8]) -> bool {
    let p = provided.as_bytes();
    // Constant-time compare; length mismatch also handled without early exit signal.
    p.ct_eq(expected).into()
}

fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for v in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(s) = v.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, val)) = part.split_once('=') {
                    out.insert(k.trim().to_string(), val.trim().to_string());
                }
            }
        }
    }
    out
}

async fn check_auth(
    state: &AdminState,
    headers: &HeaderMap,
    require_csrf: bool,
    host: Option<&str>,
) -> Result<(), StatusCode> {
    // 1. Bearer API auth (no CSRF, no Origin requirement).
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(tok) = s
                .strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
            {
                if bearer_valid(tok.trim(), &state.token) {
                    return Ok(());
                }
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }
    // 2. Session cookie.
    let cookies = parse_cookies(headers);
    if let Some(sid) = cookies.get(SESSION_COOKIE) {
        let mut sessions = state.sessions.lock().await;
        if let Some(sess) = sessions.get(sid) {
            if sess.expires > Instant::now() {
                if require_csrf {
                    // CSRF header must match.
                    let csrf_ok = headers
                        .get("x-csrf-token")
                        .and_then(|v| v.to_str().ok())
                        .map(|c| c.as_bytes().ct_eq(sess.csrf.as_bytes()).into())
                        .unwrap_or(false);
                    if !csrf_ok {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    // Explicit Origin check when present.
                    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
                        if !origin_allowed(origin, host) {
                            return Err(StatusCode::FORBIDDEN);
                        }
                    }
                }
                return Ok(());
            }
            sessions.remove(sid);
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

fn origin_allowed(origin: &str, host: Option<&str>) -> bool {
    // Allow loopback origins always (SSH-tunnel local UI).
    for prefix in [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "https://127.0.0.1",
        "https://localhost",
    ] {
        if origin.starts_with(prefix) {
            return true;
        }
    }
    // Otherwise require same-host.
    if let (Some(h), Ok(o)) = (host, origin.parse::<http::Uri>()) {
        if let Some(oh) = o.host() {
            // Compare host part of Host header (strip port).
            let h_host = h.split(':').next().unwrap_or(h);
            return oh == h_host;
        }
    }
    false
}

impl AdminState {
    async fn audit(&self, action: &str, target: &str) {
        self.app
            .store
            .append_audit("admin", action, target, "")
            .await;
    }
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/", get(ui_handler))
        .route("/admin/login", post(login_handler))
        .route("/admin/logout", post(logout_handler))
        .route("/admin/endpoints", get(list_handler))
        .route("/admin/endpoints/{id}", put(upsert_handler))
        .route("/admin/endpoints/{id}/revoke", post(revoke_handler))
        .route("/admin/status", get(status_handler))
        .route(
            "/admin/settings",
            get(settings_handler).patch(settings_patch_handler),
        )
        .route("/admin/audit", get(audit_handler))
        .route("/admin/usage", get(usage_handler))
        .route("/admin/metrics", get(metrics_handler))
        // Bound admin request bodies (labels live in JSON bodies, never URLs).
        .layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024))
        .with_state(state)
}

async fn ui_handler() -> Html<&'static str> {
    // Static shell; all data loads via the authenticated API. Every dynamic
    // string is injected with textContent (never innerHTML).
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>relay-warden admin</title>
<style>body{font-family:sans-serif;max-width:72em;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #999;padding:.3em .6em;font-size:.9em}input,select{max-width:14em}.row-form input{width:9em}</style>
</head>
<body><h1>relay-warden admin</h1>
<p>Private interface. Log in with the admin token (stored only in your secret file).</p>
<div><input id="tok" type="password" placeholder="admin token" autocomplete="off">
<button id="loginBtn">Login</button> <button id="logoutBtn">Logout</button></div>
<pre id="out">not logged in</pre>
<h2>Add endpoint</h2>
<div><input id="newId" placeholder="endpoint id (hex or base32)" size="70">
<input id="newLabel" placeholder="label">
<button id="addBtn">Add (unapproved)</button></div>
<h2>Endpoints</h2><div id="eps"></div>
<h2>Monthly budget</h2><pre id="usage"></pre>
<h2>Settings</h2><div id="settings"></div>
<h2>Recent admin events</h2><div id="audit"></div>
<script>
"use strict";
let csrf = null;
function headers(extra) {
  const h = {'Content-Type': 'application/json'};
  if (csrf) h['X-CSRF-Token'] = csrf;
  return Object.assign(h, extra || {});
}
function msg(t) { document.getElementById('out').textContent = t; }
function td(text) { const c = document.createElement('td'); c.textContent = text; return c; }
function numInput(id, val) {
  const i = document.createElement('input'); i.id = id; i.type = 'number'; i.min = '0';
  if (val !== null && val !== undefined) i.value = val;
  return i;
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  let j = null;
  try { j = await r.json(); } catch (e) { /* non-JSON error page */ }
  return {ok: r.ok, status: r.status, body: j};
}
async function login() {
  const token = document.getElementById('tok').value;
  const r = await api('login', {method: 'POST', headers: headers(), body: JSON.stringify({token: token})});
  if (r.ok) { csrf = r.body.csrf; msg('logged in'); refresh(); }
  else msg('login failed: ' + ((r.body && r.body.error) || r.status));
  document.getElementById('tok').value = '';
}
async function logout() {
  await api('logout', {method: 'POST', headers: headers()});
  csrf = null; msg('logged out');
}
async function refresh() {
  await Promise.all([refreshEndpoints(), refreshUsage(), refreshSettings(), refreshAudit()]);
}
async function refreshEndpoints() {
  const div = document.getElementById('eps'); div.textContent = '';
  const r = await api('endpoints', {headers: headers()});
  if (!r.ok) { div.textContent = 'error: ' + ((r.body && r.body.error) || r.status); return; }
  const table = document.createElement('table');
  const head = document.createElement('tr');
  ['endpoint', 'label', 'approved', 'speed', 'rx', 'tx', 'burst', 'rev', 'live', 'limits', ''].forEach(function(k) {
    const th = document.createElement('th'); th.textContent = k; head.appendChild(th);
  });
  table.appendChild(head);
  r.body.endpoints.forEach(function(e) {
    const tr = document.createElement('tr');
    tr.appendChild(td(e.endpoint_id));
    const lab = document.createElement('input'); lab.value = e.label || '';
    const labTd = document.createElement('td'); labTd.appendChild(lab); tr.appendChild(labTd);
    const app = document.createElement('input'); app.type = 'checkbox'; app.checked = !!e.approved;
    const appTd = document.createElement('td'); appTd.appendChild(app); tr.appendChild(appTd);
    const spd = document.createElement('select');
    ['default', 'custom', 'unlimited'].forEach(function(o) {
      const op = document.createElement('option'); op.value = o; op.textContent = o;
      if (e.speed_policy === o) op.selected = true;
      spd.appendChild(op);
    });
    const spdTd = document.createElement('td'); spdTd.appendChild(spd); tr.appendChild(spdTd);
    const rx = numInput(null, e.custom_rx_bps); const rxTd = document.createElement('td'); rxTd.appendChild(rx); tr.appendChild(rxTd);
    const tx = numInput(null, e.custom_tx_bps); const txTd = document.createElement('td'); txTd.appendChild(tx); tr.appendChild(txTd);
    const bu = numInput(null, e.burst_bytes); const buTd = document.createElement('td'); buTd.appendChild(bu); tr.appendChild(buTd);
    tr.appendChild(td(String(e.revision)));
    tr.appendChild(td('live=' + (e.live_connections == null ? 0 : e.live_connections)));
    const lim = (e.limits && e.limits.rx_bps != null) ? (e.limits.rx_bps + '/' + e.limits.tx_bps) : 'unlimited';
    tr.appendChild(td(lim));
    const btnTd = document.createElement('td');
    const save = document.createElement('button'); save.textContent = 'Save';
    save.onclick = async function() {
      const body = {revision: e.revision, label: lab.value, approved: app.checked, speed_policy: spd.value,
        custom_rx_bps: rx.value === '' ? null : Number(rx.value),
        custom_tx_bps: tx.value === '' ? null : Number(tx.value),
        burst_bytes: bu.value === '' ? null : Number(bu.value)};
      const r2 = await api('endpoints/' + encodeURIComponent(e.endpoint_id),
        {method: 'PUT', headers: headers(), body: JSON.stringify(body)});
      msg(r2.ok ? 'saved ' + e.endpoint_id : 'save failed: ' + ((r2.body && r2.body.error) || r2.status));
      refreshEndpoints();
    };
    const revoke = document.createElement('button'); revoke.textContent = 'Revoke';
    revoke.onclick = async function() {
      const r2 = await api('endpoints/' + encodeURIComponent(e.endpoint_id) + '/revoke',
        {method: 'POST', headers: headers()});
      msg(r2.ok ? 'revoked' : 'revoke failed: ' + ((r2.body && r2.body.error) || r2.status));
      refreshEndpoints();
    };
    btnTd.appendChild(save); btnTd.appendChild(revoke); tr.appendChild(btnTd);
    table.appendChild(tr);
  });
  div.appendChild(table);
}
async function addEndpoint() {
  const id = document.getElementById('newId').value.trim();
  const label = document.getElementById('newLabel').value;
  const r = await api('endpoints/' + encodeURIComponent(id),
    {method: 'PUT', headers: headers(), body: JSON.stringify({label: label})});
  msg(r.ok ? 'added (unapproved)' : 'add failed: ' + ((r.body && r.body.error) || r.status));
  refreshEndpoints();
}
async function refreshUsage() {
  const r = await api('usage', {headers: headers()});
  document.getElementById('usage').textContent = r.ok ? JSON.stringify(r.body, null, 1) : ('error: ' + ((r.body && r.body.error) || r.status));
}
async function refreshSettings() {
  const div = document.getElementById('settings'); div.textContent = '';
  const r = await api('settings', {headers: headers()});
  if (!r.ok) { div.textContent = 'error: ' + ((r.body && r.body.error) || r.status); return; }
  const keys = ['default_rx_bps', 'default_tx_bps', 'quota_budget_bytes', 'quota_headroom_bytes',
    'quota_overhead_pct', 'quota_chunk_bytes', 'alert_webhook_url'];
  const inputs = {};
  keys.forEach(function(k) {
    const lab = document.createElement('label'); lab.textContent = k + ': ';
    const inp = document.createElement('input');
    const v = r.body.settings[k];
    inp.value = (v === null || v === undefined) ? '' : v;
    if (k === 'alert_webhook_url') inp.size = 50;
    inputs[k] = inp; lab.appendChild(inp); div.appendChild(lab); div.appendChild(document.createElement('br'));
  });
  const save = document.createElement('button'); save.textContent = 'Save settings';
  save.onclick = async function() {
    const patch = {};
    keys.forEach(function(k) {
      const raw = inputs[k].value;
      if (raw === '') { patch[k] = null; return; }
      patch[k] = (k === 'alert_webhook_url') ? raw : Number(raw);
    });
    const r2 = await api('settings',
      {method: 'PATCH', headers: headers(), body: JSON.stringify({version: r.body.version, settings: patch})});
    msg(r2.ok ? 'settings saved' : 'settings failed: ' + ((r2.body && r2.body.error) || r2.status));
    refreshSettings();
  };
  div.appendChild(save);
  const ver = document.createElement('span'); ver.textContent = ' (version ' + r.body.version + ')';
  div.appendChild(ver);
}
async function refreshAudit() {
  const div = document.getElementById('audit'); div.textContent = '';
  const r = await api('audit?limit=20', {headers: headers()});
  if (!r.ok) { div.textContent = 'error: ' + ((r.body && r.body.error) || r.status); return; }
  const table = document.createElement('table');
  r.body.events.forEach(function(ev) {
    const tr = document.createElement('tr');
    [ev.at, ev.actor, ev.action, ev.target].forEach(function(x) { tr.appendChild(td(x || '')); });
    table.appendChild(tr);
  });
  div.appendChild(table);
}
document.getElementById('loginBtn').onclick = login;
document.getElementById('logoutBtn').onclick = logout;
document.getElementById('addBtn').onclick = addEndpoint;
</script></body></html>"#,
    )
}
#[derive(serde::Deserialize)]
struct LoginBody {
    token: String,
}

async fn login_handler(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<LoginBody>,
) -> Response {
    // Rate-limit per IP.
    {
        let mut attempts = state.login_attempts.lock().await;
        let now = Instant::now();
        let entry = attempts.entry(addr.ip().to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > LOGIN_WINDOW {
            *entry = (0, now);
        }
        if entry.0 >= LOGIN_MAX_ATTEMPTS {
            return json_err(StatusCode::TOO_MANY_REQUESTS, "too many login attempts");
        }
        entry.0 += 1;
    }
    let _ = headers; // no auth needed for login itself
    if !bearer_valid(body.token.trim(), &state.token) {
        state.audit("login_failed", "").await;
        return json_err(StatusCode::UNAUTHORIZED, "invalid token");
    }
    // Reset counter on success.
    state
        .login_attempts
        .lock()
        .await
        .remove(&addr.ip().to_string());
    let sid = random_token();
    let csrf = random_token();
    state.sessions.lock().await.insert(
        sid.clone(),
        Session {
            csrf: csrf.clone(),
            expires: Instant::now() + SESSION_TTL,
        },
    );
    state.audit("login", "").await;
    let cookie =
        format!("{SESSION_COOKIE}={sid}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=3600");
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(serde_json::json!({ "csrf": csrf })),
    )
        .into_response()
}

async fn logout_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let cookies = parse_cookies(&headers);
    if let Some(sid) = cookies.get(SESSION_COOKIE) {
        state.sessions.lock().await.remove(sid);
    }
    state.audit("logout", "").await;
    (
        StatusCode::OK,
        [(
            axum::http::header::SET_COOKIE,
            format!("{SESSION_COOKIE}=; Path=/admin; Max-Age=0"),
        )],
        axum::Json(serde_json::json!({ "ok": true })),
    )
        .into_response()
}

async fn list_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let mut out = Vec::new();
    for e in state.app.policy.list() {
        let live = state.app.policy.live_count(&e.endpoint_id);
        let mut v = serde_json::to_value(&e).unwrap_or_default();
        v["live_connections"] = live.into();
        // Escape label for any server-rendered context; JSON keeps raw too.
        v["label_escaped"] = escape_html(&e.label).into();
        // Effective limits + observed counters (Gate C). Directions state the
        // contract: both capped independently; null = unlimited (owner).
        if let Some(lim) = state.app.limiter.get(&e.endpoint_id) {
            let s = lim.stats();
            v["limits"] = serde_json::json!({
                "rx_bps": s.rx_bps,
                "tx_bps": s.tx_bps,
                "rx_bytes": s.rx_bytes,
                "tx_bytes": s.tx_bytes,
                "throttled_bytes": s.throttled_bytes,
                "throttled_wait_ms": s.throttled_wait_ms,
            });
        } else {
            v["limits"] = serde_json::json!({
                "rx_bps": null,
                "tx_bps": null,
                "note": "no active limiter (no connections yet under Gate C)",
            });
        }
        out.push(v);
    }
    axum::Json(serde_json::json!({ "endpoints": out })).into_response()
}

async fn upsert_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<EndpointUpsert>,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Err(s) = check_auth(&state, &headers, true, host.as_deref()).await {
        let msg = if s == StatusCode::FORBIDDEN {
            "forbidden"
        } else {
            "unauthorized"
        };
        return json_err(s, msg);
    }
    // One coordinator call preserves commit/audit/propagation invariants.
    match state.app.upsert_endpoint(&id, &body).await {
        Ok(rec) => (
            StatusCode::OK,
            axum::Json(serde_json::to_value(&rec).unwrap()),
        )
            .into_response(),
        Err(e)
            if e.contains("revision conflict")
                || e.contains("revision required")
                || e.contains("reread and retry")
                || e.contains("already exists") =>
        {
            json_err(StatusCode::CONFLICT, &e)
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn revoke_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Err(s) = check_auth(&state, &headers, true, host.as_deref()).await {
        let msg = if s == StatusCode::FORBIDDEN {
            "forbidden"
        } else {
            "unauthorized"
        };
        return json_err(s, msg);
    }
    match state.app.revoke_endpoint(&id).await {
        Ok((rec, had_live)) => {
            axum::Json(serde_json::json!({ "endpoint": rec, "had_live_connections": had_live }))
                .into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn status_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    // DB liveness: list is cheap; treat error as not ok.
    let db_ok = state.app.policy.store().recent_audit(1).await.is_ok();
    let snap = state.app.limiter.snapshot();
    let (mut rx_bytes, mut tx_bytes, mut throttled_bytes, mut throttled_ms) =
        (0u64, 0u64, 0u64, 0u64);
    for (_, s) in &snap {
        rx_bytes += s.rx_bytes;
        tx_bytes += s.tx_bytes;
        throttled_bytes += s.throttled_bytes;
        throttled_ms += s.throttled_wait_ms;
    }
    let quota_status = match &state.app.quota {
        Some(q) => q
            .usage()
            .await
            .unwrap_or_else(|e| serde_json::json!({"error": e})),
        None => serde_json::json!({"implemented": false}),
    };
    axum::Json(serde_json::json!({
        "service": "relay-warden",
        "version": env!("CARGO_PKG_VERSION"),
        "db_ok": db_ok,
        "live_connections": state.app.policy.live_total(),
        "approved_endpoints": state.app.policy.approved_count(),
        "limited_endpoints": snap.len(),
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "throttled_bytes": throttled_bytes,
        "throttled_wait_ms": throttled_ms,
        "admitted_total": state.app.policy.admitted_total.load(std::sync::atomic::Ordering::Relaxed),
        "denied_unknown_total": state.app.policy.denied_unknown_total.load(std::sync::atomic::Ordering::Relaxed),
        "denied_quota_total": state.app.policy.denied_quota_total.load(std::sync::atomic::Ordering::Relaxed),
        "denied_busy_total": state.app.policy.denied_busy_total.load(std::sync::atomic::Ordering::Relaxed),
        "quota": quota_status,
        "uptime_secs": state.started.elapsed().as_secs(),
    }))
    .into_response()
}

/// Prometheus exposition. Low-cardinality labels only: no endpoint IDs, IPs,
/// labels, or any request content. Process-lifetime counters reset on restart
/// by design (the quota ledger is the durable source of truth); scraping
/// nothing is required for enforcement to work.
async fn metrics_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    use std::sync::atomic::Ordering::Relaxed;
    let snap = state.app.limiter.snapshot();
    let (mut rx, mut txb, mut thr, mut thr_ms) = (0u64, 0u64, 0u64, 0u64);
    for (_, s) in &snap {
        rx += s.rx_bytes;
        txb += s.tx_bytes;
        thr += s.throttled_bytes;
        thr_ms += s.throttled_wait_ms;
    }
    let mut out = String::new();
    let gauge = |o: &mut String, name: &str, help: &str, v: u64| {
        use std::fmt::Write as _;
        let _ = writeln!(o, "# HELP {name} {help}.");
        let _ = writeln!(o, "# TYPE {name} gauge");
        let _ = writeln!(o, "{name} {v}");
    };
    let counter = |o: &mut String, name: &str, help: &str, v: u64| {
        use std::fmt::Write as _;
        let _ = writeln!(o, "# HELP {name} {help}.");
        let _ = writeln!(o, "# TYPE {name} counter");
        let _ = writeln!(o, "{name} {v}");
    };
    gauge(
        &mut out,
        "warden_live_connections",
        "Currently admitted relay connections",
        state.app.policy.live_total() as u64,
    );
    gauge(
        &mut out,
        "warden_approved_endpoints",
        "Endpoints currently approved",
        state.app.policy.approved_count() as u64,
    );
    gauge(
        &mut out,
        "warden_limited_endpoints",
        "Endpoints with an active limiter",
        snap.len() as u64,
    );
    counter(
        &mut out,
        "warden_admitted_total",
        "Admission decisions allowing connection (process lifetime)",
        state.app.policy.admitted_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_denied_unknown_total",
        "Denied: endpoint not approved",
        state.app.policy.denied_unknown_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_denied_quota_total",
        "Denied: monthly budget exhausted",
        state.app.policy.denied_quota_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_denied_busy_total",
        "Denied: connection ceilings",
        state.app.policy.denied_busy_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_limiter_rx_bytes_total",
        "Payload bytes accepted from endpoints",
        rx,
    );
    counter(
        &mut out,
        "warden_limiter_tx_bytes_total",
        "Payload bytes delivered to endpoints",
        txb,
    );
    counter(
        &mut out,
        "warden_limiter_throttled_bytes_total",
        "Bytes delayed by throughput shaping",
        thr,
    );
    counter(
        &mut out,
        "warden_limiter_throttled_wait_ms_total",
        "Observed shaping delay",
        thr_ms,
    );
    if let Some(q) = &state.app.quota {
        if let Ok(u) = q.usage().await {
            use std::fmt::Write as _;
            let period = u["period"].as_str().unwrap_or("unknown");
            let charged = u["charged_bytes"].as_u64().unwrap_or(0);
            let cutoff = u["effective_cutoff_bytes"].as_u64().unwrap_or(u64::MAX);
            let exhausted = if u["exhausted"] == true { 1 } else { 0 };
            let _ = writeln!(
                out,
                "# HELP warden_quota_charged_bytes Charged bytes in the current period."
            );
            let _ = writeln!(out, "# TYPE warden_quota_charged_bytes gauge");
            let _ = writeln!(
                out,
                "warden_quota_charged_bytes{{period=\"{period}\"}} {charged}"
            );
            let _ = writeln!(
                out,
                "# HELP warden_quota_cutoff_bytes Effective cutoff for the current period."
            );
            let _ = writeln!(out, "# TYPE warden_quota_cutoff_bytes gauge");
            let _ = writeln!(
                out,
                "warden_quota_cutoff_bytes{{period=\"{period}\"}} {cutoff}"
            );
            let _ = writeln!(
                out,
                "# HELP warden_quota_exhausted Whether the current period is exhausted."
            );
            let _ = writeln!(out, "# TYPE warden_quota_exhausted gauge");
            let _ = writeln!(
                out,
                "warden_quota_exhausted{{period=\"{period}\"}} {exhausted}"
            );
        }
    }
    ([(CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response()
}

async fn settings_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match state.app.policy.store().get_settings().await {
        Ok((settings, version)) => {
            axum::Json(serde_json::json!({ "settings": settings, "version": version }))
                .into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

#[derive(serde::Deserialize)]
struct SettingsPatch {
    version: i64,
    settings: serde_json::Map<String, serde_json::Value>,
}

async fn settings_patch_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<SettingsPatch>,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Err(s) = check_auth(&state, &headers, true, host.as_deref()).await {
        let msg = if s == StatusCode::FORBIDDEN {
            "forbidden"
        } else {
            "unauthorized"
        };
        return json_err(s, msg);
    }
    // One coordinator call: atomic commit, then audit, defaults refresh,
    // limiter propagation, and quota re-evaluation — in that order.
    match state.app.patch_settings(body.version, &body.settings).await {
        Ok((settings, version)) => {
            axum::Json(serde_json::json!({ "settings": settings, "version": version }))
                .into_response()
        }
        Err(e) if e.contains("conflict") => json_err(StatusCode::CONFLICT, &e),
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn audit_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    match state.app.policy.store().recent_audit(limit).await {
        Ok(events) => axum::Json(serde_json::json!({ "events": events })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn usage_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match &state.app.quota {
        Some(q) => match q.usage().await {
            Ok(u) => axum::Json(u).into_response(),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        },
        // No budget configured: explicit stub, never fake enforcement.
        None => axum::Json(serde_json::json!({
            "implemented": false,
            "message": "no monthly budget is configured; nothing is enforced",
        }))
        .into_response(),
    }
}

/// Read the admin token from a restricted file. Fails closed (no default).
pub fn load_admin_token(path: &str) -> Result<Vec<u8>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read admin token file: {e:#}"))?;
    let tok = raw.trim().to_string();
    if tok.len() < 16 {
        return Err("admin token too short (min 16 chars)".into());
    }
    Ok(tok.into_bytes())
}
