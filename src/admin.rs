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
    policy: Arc<PolicyManager>,
    limiter: Arc<LimiterMap>,
    quota: Option<Arc<QuotaManager>>,
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
        Self {
            policy,
            limiter,
            quota,
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
    // Static shell; data loads via fetch (so HTML itself needs no auth).
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>relay-warden admin</title></head>
<body><h1>relay-warden admin</h1>
<p>Private interface. Log in with the admin token (stored only in your secret file).</p>
<div><input id="tok" type="password" placeholder="admin token" autocomplete="off">
<button onclick="login()">Login</button> <button onclick="logout()">Logout</button></div>
<pre id="out">not logged in</pre>
<h2>Endpoints</h2><div id="eps"></div>
<h2>Monthly budget</h2><pre id="usage"></pre>
<script>
let csrf=null;
function headers(extra) {{
  const h={{'Content-Type':'application/json'}};
  if(csrf) h['X-CSRF-Token']=csrf;
  return Object.assign(h, extra||{{}});
}}
async function login() {{
  const token=document.getElementById('tok').value;
  const r=await fetch('login',{{method:'POST',headers:headers(),body:JSON.stringify({{token}})}});
  const j=await r.json();
  if(r.ok){{csrf=j.csrf;document.getElementById('out').textContent='logged in';refresh();}}
  else document.getElementById('out').textContent='login failed: '+(j.error||r.status);
  document.getElementById('tok').value='';
}}
async function logout(){{await fetch('logout',{{method:'POST',headers:headers()}});csrf=null;document.getElementById('out').textContent='logged out';}}
async function refresh(){{
  const r=await fetch('endpoints',{{headers:headers()}});
  const j=await r.json();
  const div=document.getElementById('eps');div.textContent='';
  if(!r.ok){{div.textContent='error: '+(j.error||r.status);return;}}
  const table=document.createElement('table');
  for(const e of j.endpoints){{
    const tr=document.createElement('tr');
    for(const k of ['endpoint_id','label','approved','speed_policy','revision']){{
      const td=document.createElement('td');td.textContent=e[k];tr.appendChild(td);
    }}
    const td=document.createElement('td');td.textContent='live='+(e.live_connections??0);tr.appendChild(td);
    table.appendChild(tr);
  }}
  div.appendChild(table);
  const u=await fetch('usage',{headers:headers()});
  const uj=await u.json();
  document.getElementById('usage').textContent=u.ok?JSON.stringify(uj,null,1):('error: '+(uj.error||u.status));
}}
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
        state
            .policy
            .store()
            .append_audit("admin", "login_failed", "", "")
            .await;
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
    state
        .policy
        .store()
        .append_audit("admin", "login", "", "")
        .await;
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
    state
        .policy
        .store()
        .append_audit("admin", "logout", "", "")
        .await;
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
    for e in state.policy.list() {
        let live = state.policy.live_count(&e.endpoint_id);
        let mut v = serde_json::to_value(&e).unwrap_or_default();
        v["live_connections"] = live.into();
        // Escape label for any server-rendered context; JSON keeps raw too.
        v["label_escaped"] = escape_html(&e.label).into();
        // Effective limits + observed counters (Gate C). Directions state the
        // contract: both capped independently; null = unlimited (owner).
        if let Some(lim) = state.limiter.get(&e.endpoint_id) {
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
    match state.policy.upsert(&id, &body).await {
        Ok(rec) => {
            state
                .policy
                .store()
                .append_audit("admin", "endpoint_upsert", &id, "")
                .await;
            // Push the new limits into the live limiter: no restart or
            // reconnect needed for the transfer to reshape.
            state.limiter.apply_record(
                &rec,
                &state.policy.defaults_snapshot(),
                std::time::Instant::now(),
            );
            // If approval was removed, disconnect live (same as revoke path).
            if !rec.approved {
                // Best-effort; post-register revalidation covers in-flight.
                if let Ok(id) = rec.endpoint_id.parse() {
                    state.policy.revalidate(&id);
                }
            }
            (
                StatusCode::OK,
                axum::Json(serde_json::to_value(&rec).unwrap()),
            )
                .into_response()
        }
        Err(e) if e.contains("revision conflict") || e.contains("revision required") => {
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
    match state.policy.revoke(&id).await {
        Ok((rec, had_live)) => {
            state
                .policy
                .store()
                .append_audit("admin", "endpoint_revoke", &id, "")
                .await;
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
    let db_ok = state.policy.store().recent_audit(1).await.is_ok();
    let snap = state.limiter.snapshot();
    let (mut rx_bytes, mut tx_bytes, mut throttled_bytes, mut throttled_ms) =
        (0u64, 0u64, 0u64, 0u64);
    for (_, s) in &snap {
        rx_bytes += s.rx_bytes;
        tx_bytes += s.tx_bytes;
        throttled_bytes += s.throttled_bytes;
        throttled_ms += s.throttled_wait_ms;
    }
    let quota_status = match &state.quota {
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
        "live_connections": state.policy.live_total(),
        "approved_endpoints": state.policy.approved_count(),
        "limited_endpoints": snap.len(),
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "throttled_bytes": throttled_bytes,
        "throttled_wait_ms": throttled_ms,
        "admitted_total": state.policy.admitted_total.load(std::sync::atomic::Ordering::Relaxed),
        "denied_unknown_total": state.policy.denied_unknown_total.load(std::sync::atomic::Ordering::Relaxed),
        "denied_quota_total": state.policy.denied_quota_total.load(std::sync::atomic::Ordering::Relaxed),
        "denied_busy_total": state.policy.denied_busy_total.load(std::sync::atomic::Ordering::Relaxed),
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
    let snap = state.limiter.snapshot();
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
        state.policy.live_total() as u64,
    );
    gauge(
        &mut out,
        "warden_approved_endpoints",
        "Endpoints currently approved",
        state.policy.approved_count() as u64,
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
        state.policy.admitted_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_denied_unknown_total",
        "Denied: endpoint not approved",
        state.policy.denied_unknown_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_denied_quota_total",
        "Denied: monthly budget exhausted",
        state.policy.denied_quota_total.load(Relaxed),
    );
    counter(
        &mut out,
        "warden_denied_busy_total",
        "Denied: connection ceilings",
        state.policy.denied_busy_total.load(Relaxed),
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
    if let Some(q) = &state.quota {
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
    match state.policy.store().get_settings().await {
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
    match state
        .policy
        .store()
        .patch_settings(body.version, &body.settings)
        .await
    {
        Ok((settings, version)) => {
            state
                .policy
                .store()
                .append_audit("admin", "settings_patch", "", "")
                .await;
            // New ordinary defaults reshape live default-policy limiters.
            if let Ok(d) = state.policy.refresh_defaults().await {
                state
                    .limiter
                    .apply_all(&state.policy.list(), &d, std::time::Instant::now());
            }
            // New budget re-evaluates the ledger (may exhaust or reopen).
            if let Some(q) = &state.quota {
                q.refresh().await;
                state
                    .policy
                    .store()
                    .append_audit("admin", "quota_reevaluated", "", "")
                    .await;
            }
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
    match state.policy.store().recent_audit(limit).await {
        Ok(events) => axum::Json(serde_json::json!({ "events": events })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn usage_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match &state.quota {
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
