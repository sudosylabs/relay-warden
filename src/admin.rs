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
    network: Option<Arc<crate::network::NetworkGuard>>,
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
            network: None,
        }
    }

    pub fn with_network(mut self, network: Arc<crate::network::NetworkGuard>) -> Self {
        self.network = Some(network);
        self
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
    let Ok(uri) = origin.parse::<http::Uri>() else {
        return false;
    };
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return false;
    }
    uri.authority()
        .zip(host)
        .is_some_and(|(a, h)| a.as_str().eq_ignore_ascii_case(h))
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
        .route("/admin/admin.css", get(css_handler))
        .route("/admin/admin.js", get(js_handler))
        .route("/admin/navigation.js", get(navigation_handler))
        .route("/admin/session", get(session_handler))
        .route("/admin/pending", get(pending_handler))
        .route("/admin/pending/{id}/dismiss", post(dismiss_handler))
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
        .layer(axum::middleware::map_response(|mut response: Response| async move {
            let h = response.headers_mut();
            h.insert("cache-control", "no-store".parse().unwrap());
            h.insert("x-content-type-options", "nosniff".parse().unwrap());
            h.insert("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".parse().unwrap());
            response
        }))
        .with_state(state)
}

async fn ui_handler() -> Html<&'static str> {
    Html(include_str!("../web/admin.html"))
}

async fn css_handler() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/admin.css"),
    )
}

async fn js_handler() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/admin.js"),
    )
}

async fn navigation_handler() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/navigation.mjs"),
    )
}

async fn session_handler(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let cookies = parse_cookies(&headers);
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, s| s.expires > Instant::now());
    match cookies.get(SESSION_COOKIE).and_then(|id| sessions.get(id)) {
        Some(session) => axum::Json(serde_json::json!({
            "authenticated": true, "csrf": session.csrf,
            "expires_in_secs": session.expires.saturating_duration_since(Instant::now()).as_secs()
        }))
        .into_response(),
        None => json_err(StatusCode::UNAUTHORIZED, "session expired"),
    }
}

#[derive(serde::Deserialize, Default)]
struct ListQuery {
    page: Option<usize>,
    limit: Option<usize>,
    #[serde(default)]
    q: String,
}

#[derive(serde::Serialize)]
struct Pagination {
    page: usize,
    page_size: usize,
    total: usize,
    total_pages: usize,
}

impl ListQuery {
    fn request(&self) -> Result<Option<PageRequest>, &'static str> {
        let Some(page) = self.page else {
            return Ok(None);
        };
        let size = self.limit.unwrap_or(20);
        if page == 0 || size == 0 {
            return Err("page and limit must be positive");
        }
        Ok(Some(PageRequest {
            page,
            size: size.min(200),
        }))
    }

    fn bounds(&self, total: usize) -> Result<Option<Pagination>, &'static str> {
        Ok(self.request()?.map(|r| r.bounds(total)))
    }
}

struct PageRequest {
    page: usize,
    size: usize,
}
impl PageRequest {
    fn bounds(&self, total: usize) -> Pagination {
        let total_pages = total.div_ceil(self.size).max(1);
        Pagination {
            page: self.page.min(total_pages),
            page_size: self.size,
            total,
            total_pages,
        }
    }
}

fn page_rows<T>(rows: Vec<T>, page: &Option<Pagination>) -> Vec<T> {
    match page {
        Some(p) => rows
            .into_iter()
            .skip((p.page - 1) * p.page_size)
            .take(p.page_size)
            .collect(),
        None => rows,
    }
}

async fn pending_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let approval = state.app.policy.access_summary()["approval_required"]
        .as_bool()
        .unwrap_or(true);
    let rows = if approval {
        state.app.policy.pending()
    } else {
        state.app.policy.observed_unknown()
    };
    let page = match query.bounds(rows.len()) {
        Ok(p) => p,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e),
    };
    axum::Json(serde_json::json!({"requests": page_rows(rows, &page), "pagination": page, "mode": if approval {"requests"} else {"observed"}}))
        .into_response()
}

async fn dismiss_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    if let Err(s) = check_auth(&state, &headers, true, host).await {
        return json_err(s, "unauthorized");
    }
    match state.app.policy.dismiss_pending(&id) {
        Ok(()) => {
            state.audit("pending_dismiss", &id).await;
            axum::Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e),
    }
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
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if !origin_allowed(origin, headers.get("host").and_then(|v| v.to_str().ok())) {
            return json_err(StatusCode::FORBIDDEN, "forbidden origin");
        }
    }
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
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, s| s.expires > Instant::now());
    if sessions.len() >= 256 {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "too many active sessions");
    }
    sessions.insert(
        sid.clone(),
        Session {
            csrf: csrf.clone(),
            expires: Instant::now() + SESSION_TTL,
        },
    );
    drop(sessions);
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
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    if let Err(s) = check_auth(&state, &headers, true, host).await {
        return json_err(s, "unauthorized");
    }
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

async fn list_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if check_auth(&state, &headers, false, None).await.is_err() {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let mut out = Vec::new();
    let search = query.q.trim().to_lowercase();
    let rows: Vec<_> = state
        .app
        .policy
        .list()
        .into_iter()
        .filter(|e| {
            format!("{} {}", e.label, e.endpoint_id)
                .to_lowercase()
                .contains(&search)
        })
        .collect();
    let page = match query.bounds(rows.len()) {
        Ok(p) => p,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e),
    };
    for e in page_rows(rows, &page) {
        let live = state.app.policy.live_count(&e.endpoint_id);
        let mut v = serde_json::to_value(&e).unwrap_or_default();
        v["live_connections"] = live.into();
        v["observation"] =
            serde_json::to_value(state.app.policy.observation(&e.endpoint_id)).unwrap_or_default();
        let effective =
            crate::limiter::resolve_effective(Some(&e), &state.app.policy.defaults_snapshot());
        v["effective_limits"] =
            serde_json::json!({"rx_bps": effective.rx_bps, "tx_bps": effective.tx_bps});
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
    axum::Json(serde_json::json!({ "endpoints": out, "pagination": page })).into_response()
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
        "access_policy": state.app.policy.access_summary(),
        "pending_requests": state.app.policy.pending().len(),
        "observed_devices": state.app.policy.observed_unknown().len(),
        "network_limits": state.network.as_ref().map(|n| n.summary()),
        "denied_token_total": state.app.policy.denied_token_total.load(std::sync::atomic::Ordering::Relaxed),
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
    if let Some(page) = q.get("page") {
        let Ok(page) = page.parse::<usize>() else {
            return json_err(StatusCode::BAD_REQUEST, "invalid page");
        };
        let limit = match q.get("limit").map(|s| s.parse::<usize>()).transpose() {
            Ok(limit) => limit,
            Err(_) => return json_err(StatusCode::BAD_REQUEST, "invalid limit"),
        };
        let request = match (ListQuery {
            page: Some(page),
            limit,
            q: String::new(),
        })
        .request()
        {
            Ok(Some(request)) => request,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, e),
            Ok(None) => unreachable!("page was supplied"),
        };
        return match state.app.store.audit_page(request.page, request.size).await {
            Ok((events, total, _)) => {
                axum::Json(serde_json::json!({"events":events,"pagination": request.bounds(total)}))
                    .into_response()
            }
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        };
    }
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
