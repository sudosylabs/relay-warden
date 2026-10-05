//! Admission policy for local/dev use (Gate A legacy).
//!
//! A thin wrapper over upstream `AccessControl`. Production uses
//! `PolicyManager` (SQLite-backed + live revocation); this stays for tests
//! and minimal setups. Unknown endpoints are denied either way.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
};

use iroh_base::EndpointId;
use iroh_relay::server::{Access, AccessControl, ClientRequest};

use crate::policy::canonical_endpoint_id;

/// Simple in-memory allowlist with a per-endpoint connection ceiling.
///
/// - Empty allowlist + `open = true`: admit everyone (local dev default).
/// - Otherwise: admit only IDs in the set. Unknown endpoints are denied.
#[derive(Debug)]
pub struct Allowlist {
    open: bool,
    allowed: RwLock<HashSet<EndpointId>>,
    live: RwLock<HashMap<String, usize>>,
    max_per_endpoint: usize,
    pub admitted_total: AtomicU64,
    pub denied_total: AtomicU64,
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::open()
    }
}

impl Allowlist {
    /// Open admission (dev only). Production must use closed + explicit IDs.
    pub fn open() -> Self {
        Self {
            open: true,
            allowed: RwLock::new(HashSet::new()),
            live: RwLock::new(HashMap::new()),
            max_per_endpoint: 16,
            admitted_total: AtomicU64::new(0),
            denied_total: AtomicU64::new(0),
        }
    }

    /// Closed admission with an initial set.
    pub fn closed(ids: HashSet<EndpointId>) -> Self {
        Self {
            open: false,
            allowed: RwLock::new(ids),
            live: RwLock::new(HashMap::new()),
            max_per_endpoint: 16,
            admitted_total: AtomicU64::new(0),
            denied_total: AtomicU64::new(0),
        }
    }

    /// Add an endpoint ID at runtime (Gate B will persist + broadcast).
    pub fn allow(&self, id: EndpointId) {
        self.allowed.write().expect("lock").insert(id);
    }

    /// Remove an endpoint ID. Existing connections are disconnected by the
    /// caller via `Clients::disconnect` (wired in Gate B).
    pub fn deny(&self, id: &EndpointId) {
        self.allowed.write().expect("lock").remove(id);
    }

    pub fn live_total(&self) -> usize {
        self.live.read().expect("lock").values().sum()
    }
}

impl AccessControl for Allowlist {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let id = request.endpoint_id();
        if !self.open && !self.allowed.read().expect("lock").contains(&id) {
            self.denied_total.fetch_add(1, Ordering::Relaxed);
            return Access::Deny {
                reason: Some("endpoint not approved".to_string()),
            };
        }
        let key = canonical_endpoint_id(&id);
        let mut live = self.live.write().expect("lock");
        let n = live.get(&key).copied().unwrap_or(0);
        if n >= self.max_per_endpoint {
            self.denied_total.fetch_add(1, Ordering::Relaxed);
            return Access::Deny {
                reason: Some("too many connections for endpoint".to_string()),
            };
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
        let key = canonical_endpoint_id(&endpoint_id);
        let mut live = self.live.write().expect("lock");
        if let Some(n) = live.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                live.remove(&key);
            }
        }
    }
}
