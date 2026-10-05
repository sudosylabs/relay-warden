//! Endpoint policy records and admission manager (Gate B).
//!
//! SQLite is the durable store; an in-memory cache serves the admission hot
//! path so packet/handshake processing never does synchronous SQLite I/O.
//! Revocation closes the auth/register race via publish-then-disconnect on
//! the revoke path and register-then-revalidate on the admit path.

use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use chrono::Utc;
use iroh_base::EndpointId;
use iroh_relay::server::{Access, AccessControl, ClientRequest};
use serde::{Deserialize, Serialize};

use crate::store::Store;

/// Speed policy: explicit, never ambiguous zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpeedPolicy {
    Default,
    Custom,
    Unlimited,
}

impl FromStr for SpeedPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "default" => Ok(Self::Default),
            "custom" => Ok(Self::Custom),
            "unlimited" => Ok(Self::Unlimited),
            _ => Err(format!("unknown speed_policy: {s}")),
        }
    }
}

impl fmt::Display for SpeedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Custom => write!(f, "custom"),
            Self::Unlimited => write!(f, "unlimited"),
        }
    }
}

/// Durable endpoint record. `revision` guards lost updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPolicy {
    pub endpoint_id: String,
    pub label: String,
    pub approved: bool,
    pub speed_policy: SpeedPolicy,
    pub custom_rx_bps: Option<i64>,
    pub custom_tx_bps: Option<i64>,
    pub burst_bytes: Option<i64>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl EndpointPolicy {
    pub fn new(endpoint_id: String, label: String) -> Self {
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        Self {
            endpoint_id,
            label,
            approved: false,
            speed_policy: SpeedPolicy::Default,
            custom_rx_bps: None,
            custom_tx_bps: None,
            burst_bytes: None,
            revision: 1,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

/// Three-state field update: omitted leaves the value unchanged, explicit
/// `null` clears it, and a value sets it. Plain `Option<Option<T>>` cannot
/// express this with serde (JSON `null` and a missing field both become
/// `None`), so clearing a custom cap back to `unlimited` needs this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriState<T> {
    /// Field omitted: keep the stored value.
    #[default]
    Unchanged,
    /// Explicit `null`: clear the stored value.
    Clear,
    /// A new value.
    Set(T),
}

impl<'de, T> serde::Deserialize<'de> for TriState<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TriStateVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T> serde::de::Visitor<'de> for TriStateVisitor<T>
        where
            T: serde::Deserialize<'de>,
        {
            type Value = TriState<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("omitted, null, or a value")
            }

            fn visit_none<E>(self) -> Result<TriState<T>, E>
            where
                E: serde::de::Error,
            {
                Ok(TriState::Clear)
            }

            fn visit_unit<E>(self) -> Result<TriState<T>, E>
            where
                E: serde::de::Error,
            {
                Ok(TriState::Clear)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<TriState<T>, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                T::deserialize(deserializer).map(TriState::Set)
            }
        }
        deserializer.deserialize_option(TriStateVisitor(std::marker::PhantomData))
    }
}

/// Input for create/update. `revision` is required for updates.
/// Directional rates are tri-state: omitted leaves the value unchanged,
/// explicit `null` clears it, and a number sets it — so a custom cap can be
/// removed again (e.g. when switching to `unlimited`).
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointUpsert {
    pub label: Option<String>,
    pub approved: Option<bool>,
    pub speed_policy: Option<String>,
    #[serde(default)]
    pub custom_rx_bps: TriState<i64>,
    #[serde(default)]
    pub custom_tx_bps: TriState<i64>,
    #[serde(default)]
    pub burst_bytes: TriState<i64>,
    pub revision: Option<i64>,
}

pub fn validate_endpoint_id(s: &str) -> Result<EndpointId, String> {
    s.parse::<EndpointId>()
        .map_err(|e| format!("invalid endpoint_id: {e:#}"))
}

/// Parse an endpoint ID and return its canonical (hex) spelling.
/// Admission looks up canonical hex, so every domain entry point must store
/// and query this form — never the operator's original spelling.
pub fn canonicalize_endpoint_id(s: &str) -> Result<String, String> {
    Ok(validate_endpoint_id(s)?.to_string())
}

/// Best-effort canonicalization for lookups: unparseable input simply misses.
pub fn canonicalize_for_lookup(s: &str) -> String {
    s.parse::<EndpointId>()
        .map(|id| id.to_string())
        .unwrap_or_else(|_| s.to_string())
}

pub fn canonical_endpoint_id(id: &EndpointId) -> String {
    id.to_string()
}

pub fn validate_label(s: &str) -> Result<String, String> {
    if s.len() > 128 {
        return Err("label too long (max 128 chars)".into());
    }
    if s.contains('\0') {
        return Err("label contains NUL".into());
    }
    Ok(s.to_string())
}

fn validate_bps(v: Option<i64>, name: &str) -> Result<Option<i64>, String> {
    match v {
        None => Ok(None),
        Some(n) if n > 0 && n <= 100_000_000_000 => Ok(Some(n)),
        Some(_) => Err(format!("{name} must be a positive integer <= 100GB/s")),
    }
}

fn validate_burst(v: Option<i64>) -> Result<Option<i64>, String> {
    match v {
        None => Ok(None),
        Some(n) if n > 0 && n <= 1_000_000_000 => Ok(Some(n)),
        Some(_) => Err("burst_bytes must be positive <= 1GB".into()),
    }
}

/// Apply and validate an upsert onto an existing (or new) record.
pub fn apply_upsert(
    existing: Option<&EndpointPolicy>,
    endpoint_id: &str,
    input: &EndpointUpsert,
) -> Result<EndpointPolicy, String> {
    validate_endpoint_id(endpoint_id)?;
    let mut rec = existing
        .cloned()
        .unwrap_or_else(|| EndpointPolicy::new(endpoint_id.to_string(), String::new()));

    if let Some(ex) = existing {
        match input.revision {
            Some(r) if r == ex.revision => {}
            Some(r) => {
                return Err(format!(
                    "revision conflict: expected {}, got {r}",
                    ex.revision
                ))
            }
            None => return Err("revision required for update".into()),
        }
    }

    if let Some(label) = &input.label {
        rec.label = validate_label(label)?;
    }
    if let Some(approved) = input.approved {
        rec.approved = approved;
    }
    if let Some(sp) = &input.speed_policy {
        rec.speed_policy = sp.parse::<SpeedPolicy>()?;
    }
    match input.custom_rx_bps {
        TriState::Unchanged => {}
        TriState::Clear => rec.custom_rx_bps = None,
        TriState::Set(v) => rec.custom_rx_bps = validate_bps(Some(v), "custom_rx_bps")?,
    }
    match input.custom_tx_bps {
        TriState::Unchanged => {}
        TriState::Clear => rec.custom_tx_bps = None,
        TriState::Set(v) => rec.custom_tx_bps = validate_bps(Some(v), "custom_tx_bps")?,
    }
    match input.burst_bytes {
        TriState::Unchanged => {}
        TriState::Clear => rec.burst_bytes = None,
        TriState::Set(v) => rec.burst_bytes = validate_burst(Some(v))?,
    }

    // Custom requires at least one direction; unlimited must not carry customs.
    match rec.speed_policy {
        SpeedPolicy::Custom => {
            if rec.custom_rx_bps.is_none() && rec.custom_tx_bps.is_none() {
                return Err("custom policy requires custom_rx_bps and/or custom_tx_bps".into());
            }
        }
        SpeedPolicy::Unlimited => {
            if rec.custom_rx_bps.is_some() || rec.custom_tx_bps.is_some() {
                return Err("unlimited policy must not set custom_*_bps".into());
            }
        }
        SpeedPolicy::Default => {}
    }

    rec.updated_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if existing.is_some() {
        rec.revision += 1;
    }
    Ok(rec)
}

/// Escape for HTML rendering (labels are admin-supplied).
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Admission manager: durable store + in-memory cache + live counts.
///
/// `clients` is set after construction (circular with `RelayState`); the
/// admit path revalidates after `register` via [`PolicyManager::revalidate`].
#[derive(Debug)]
pub struct PolicyManager {
    store: Arc<Store>,
    /// endpoint_id string -> record.
    cache: RwLock<HashMap<String, EndpointPolicy>>,
    /// endpoint_id string -> live connection count.
    live: RwLock<HashMap<String, usize>>,
    /// Ordinary-endpoint defaults (from settings; refreshed on patch/startup).
    defaults: RwLock<crate::limiter::Defaults>,
    /// Late-bound registry for post-register revalidation + revoke disconnect.
    clients: RwLock<Option<iroh_relay::server::clients::Clients>>,
    /// Shared exhaustion flag (Gate D). Read on the admission hot path so
    /// new connections are denied without SQLite I/O.
    quota_exhausted: RwLock<Option<Arc<AtomicBool>>>,
    /// Per-endpoint concurrent connection ceiling (`None` = unbounded).
    /// Checked and incremented atomically with admission.
    max_per_endpoint: RwLock<Option<usize>>,
    /// Admission outcome counters (process lifetime; the ledger is durable,
    /// these reset on restart by design).
    pub admitted_total: AtomicU64,
    pub denied_unknown_total: AtomicU64,
    pub denied_quota_total: AtomicU64,
    pub denied_busy_total: AtomicU64,
}

impl PolicyManager {
    pub async fn open(store: Arc<Store>) -> Result<Arc<Self>, String> {
        let all = store.list_endpoints().await?;
        let mut map = HashMap::new();
        for e in all {
            map.insert(e.endpoint_id.clone(), e);
        }
        let mgr = Arc::new(Self {
            store,
            cache: RwLock::new(map),
            live: RwLock::new(HashMap::new()),
            defaults: RwLock::new(crate::limiter::Defaults::default()),
            clients: RwLock::new(None),
            quota_exhausted: RwLock::new(None),
            max_per_endpoint: RwLock::new(Some(16)),
            admitted_total: AtomicU64::new(0),
            denied_unknown_total: AtomicU64::new(0),
            denied_quota_total: AtomicU64::new(0),
            denied_busy_total: AtomicU64::new(0),
        });
        mgr.refresh_defaults().await?;
        Ok(mgr)
    }

    pub fn set_quota_exhausted(&self, flag: Option<Arc<AtomicBool>>) {
        *self.quota_exhausted.write().expect("lock") = flag;
    }

    /// Operator-tunable per-endpoint connection ceiling.
    pub fn set_max_per_endpoint(&self, cap: Option<usize>) {
        *self.max_per_endpoint.write().expect("lock") = cap;
    }

    pub fn quota_exhausted(&self) -> bool {
        self.quota_exhausted
            .read()
            .expect("lock")
            .as_ref()
            .map(|f| f.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Disconnect every connection for every known endpoint. Used on quota
    /// exhaustion (including owner endpoints). Unknown IDs return false and
    /// are skipped; in-flight admissions are caught by `revalidate`.
    pub fn disconnect_all(&self) {
        if let Some(c) = self.clients.read().expect("lock").clone() {
            let ids: Vec<EndpointId> = self
                .cache
                .read()
                .expect("lock")
                .keys()
                .filter_map(|s| s.parse().ok())
                .collect();
            for id in ids {
                c.disconnect(id, None);
            }
        }
    }

    /// Re-read ordinary defaults from settings. Called at startup and after
    /// each settings patch so live limiters can be re-applied.
    pub async fn refresh_defaults(&self) -> Result<crate::limiter::Defaults, String> {
        let (settings, _) = self.store.get_settings().await?;
        let get = |k: &str| settings.get(k).and_then(|v| v.as_i64()).map(|n| n as u64);
        let d = crate::limiter::Defaults {
            rx_bps: get("default_rx_bps"),
            tx_bps: get("default_tx_bps"),
        };
        *self.defaults.write().expect("lock") = d;
        Ok(d)
    }

    pub fn defaults_snapshot(&self) -> crate::limiter::Defaults {
        *self.defaults.read().expect("lock")
    }

    pub fn set_clients(&self, clients: iroh_relay::server::clients::Clients) {
        *self.clients.write().expect("lock") = Some(clients);
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    fn is_approved(&self, id: &EndpointId) -> bool {
        let key = canonical_endpoint_id(id);
        self.cache
            .read()
            .expect("lock")
            .get(&key)
            .map(|e| e.approved)
            .unwrap_or(false)
    }

    /// Upsert + publish to cache. Returns the stored record.
    /// Canonicalizing compare-and-swap: the revision check and the write
    /// are one database statement, so concurrent edits on the same revision
    /// cannot both succeed and a stale edit cannot overwrite a concurrent
    /// revocation. The cache is published only after the commit; on conflict
    /// it is refreshed from the winning row.
    pub async fn upsert(
        &self,
        endpoint_id: &str,
        input: &EndpointUpsert,
    ) -> Result<EndpointPolicy, String> {
        let endpoint_id = canonicalize_endpoint_id(endpoint_id)?;
        let existing = self.cache.read().expect("lock").get(&endpoint_id).cloned();
        let rec = apply_upsert(existing.as_ref(), &endpoint_id, input)?;
        let expected = existing.as_ref().map(|e| e.revision);
        match self.store.upsert_endpoint_cas(&rec, expected).await {
            Ok(()) => {
                self.cache
                    .write()
                    .expect("lock")
                    .insert(endpoint_id, rec.clone());
                Ok(rec)
            }
            Err(e) => {
                // Refresh the cache from the winning row so the next attempt
                // validates against current state, then report the conflict.
                if let Ok(cur) = self.store.get_endpoint(&endpoint_id).await {
                    self.cache.write().expect("lock").insert(endpoint_id, cur);
                }
                Err(e)
            }
        }
    }

    /// Revoke: publish deny, then disconnect existing + in-flight (which
    /// revalidate after register and kill themselves if still denied).
    pub async fn revoke(&self, endpoint_id: &str) -> Result<(EndpointPolicy, bool), String> {
        let endpoint_id = canonicalize_endpoint_id(endpoint_id)?;
        let rec = self.store.set_approved(&endpoint_id, false).await?;
        self.cache
            .write()
            .expect("lock")
            .insert(endpoint_id.to_string(), rec.clone());
        let had_live = self.live_count(&endpoint_id) > 0;
        if let Ok(id) = endpoint_id.parse::<EndpointId>() {
            if let Some(c) = self.clients.read().expect("lock").clone() {
                c.disconnect(id, None);
            }
        }
        Ok((rec, had_live))
    }

    /// Post-register revalidation: if the endpoint was revoked between
    /// `on_connect` and `register`, disconnect it now. Either this or the
    /// revoke-path disconnect lands after the race window. Quota exhaustion
    /// in the same window is closed the same way.
    pub fn revalidate(&self, id: &EndpointId) {
        if !self.is_approved(id) || self.quota_exhausted() {
            if let Some(c) = self.clients.read().expect("lock").clone() {
                c.disconnect(*id, None);
            }
        }
    }

    pub fn get(&self, endpoint_id: &str) -> Option<EndpointPolicy> {
        let key = canonicalize_for_lookup(endpoint_id);
        self.cache.read().expect("lock").get(&key).cloned()
    }

    pub fn list(&self) -> Vec<EndpointPolicy> {
        let mut v: Vec<_> = self.cache.read().expect("lock").values().cloned().collect();
        v.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        v
    }

    pub fn live_count(&self, endpoint_id: &str) -> usize {
        self.live
            .read()
            .expect("lock")
            .get(endpoint_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn live_total(&self) -> usize {
        self.live.read().expect("lock").values().sum()
    }

    pub fn approved_count(&self) -> usize {
        self.cache
            .read()
            .expect("lock")
            .values()
            .filter(|e| e.approved)
            .count()
    }

    fn live_dec(&self, id: EndpointId) {
        let key = canonical_endpoint_id(&id);
        let mut live = self.live.write().expect("lock");
        if let Some(n) = live.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                live.remove(&key);
            }
        }
    }
}

impl AccessControl for PolicyManager {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        // Exhaustion denies new admissions first (fail-closed, no SQLite here).
        if self.quota_exhausted() {
            self.denied_quota_total.fetch_add(1, Ordering::Relaxed);
            return Access::Deny {
                reason: Some("monthly relay budget exhausted".to_string()),
            };
        }
        let id = request.endpoint_id();
        if !self.is_approved(&id) {
            self.denied_unknown_total.fetch_add(1, Ordering::Relaxed);
            return Access::Deny {
                reason: Some("endpoint not approved".to_string()),
            };
        }
        // Approval + per-endpoint ceiling + live increment under one lock.
        let key = canonical_endpoint_id(&id);
        let mut live = self.live.write().expect("lock");
        let n = live.get(&key).copied().unwrap_or(0);
        if let Some(cap) = *self.max_per_endpoint.read().expect("lock") {
            if n >= cap {
                self.denied_busy_total.fetch_add(1, Ordering::Relaxed);
                return Access::Deny {
                    reason: Some("too many connections for endpoint".to_string()),
                };
            }
        }
        live.insert(key, n + 1);
        self.admitted_total.fetch_add(1, Ordering::Relaxed);
        Access::Allow
    }

    fn on_disconnect(
        &self,
        endpoint_id: EndpointId,
        _connection_id: iroh_relay::server::ConnectionId,
    ) {
        self.live_dec(endpoint_id);
    }
}
