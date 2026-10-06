//! Startup access policy and bounded, ephemeral connection observations.
//!
//! No token, request URL or forwarded header is retained. IPs are the socket
//! peer, not a trusted claim from a client. Pending requests expire after 24h
//! and reset on restart; durable approvals live in the policy store.

use chrono::Utc;
use serde::Serialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

pub const MAX_OBSERVATIONS: usize = 1000;
pub const OBSERVATION_TTL: Duration = Duration::from_secs(86400);

pub struct AdmissionPolicy {
    pub require_approval: bool,
    token: Option<Vec<u8>>,
}

impl std::fmt::Debug for AdmissionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionPolicy")
            .field("require_approval", &self.require_approval)
            .field("token_required", &self.token.is_some())
            .finish()
    }
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self::new(true, None)
    }
}

impl AdmissionPolicy {
    pub fn new(require_approval: bool, token: Option<Vec<u8>>) -> Self {
        Self {
            require_approval,
            token,
        }
    }
    pub fn token_required(&self) -> bool {
        self.token.is_some()
    }
    pub fn accepts_token(&self, provided: Option<&str>) -> bool {
        match &self.token {
            None => true,
            Some(expected) => provided
                .map(|p| bool::from(p.as_bytes().ct_eq(expected)))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub endpoint_id: String,
    pub observed_ip: Option<IpAddr>,
    pub first_seen: String,
    pub last_seen: String,
    pub attempts: u64,
    #[serde(skip)]
    touched: Instant,
}

#[derive(Debug, Default)]
pub struct Observations(HashMap<String, Observation>);

impl Observations {
    fn expire(&mut self) {
        self.0.retain(|_, o| o.touched.elapsed() < OBSERVATION_TTL);
    }
    pub fn record(&mut self, id: String, ip: Option<IpAddr>) {
        self.expire();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if let Some(o) = self.0.get_mut(&id) {
            o.observed_ip = ip;
            o.last_seen = now;
            o.attempts = o.attempts.saturating_add(1);
            o.touched = Instant::now();
        } else if self.0.len() < MAX_OBSERVATIONS {
            self.0.insert(
                id.clone(),
                Observation {
                    endpoint_id: id,
                    observed_ip: ip,
                    first_seen: now.clone(),
                    last_seen: now,
                    attempts: 1,
                    touched: Instant::now(),
                },
            );
        }
    }
    pub fn list(&mut self) -> Vec<Observation> {
        self.expire();
        let mut rows: Vec<_> = self.0.values().cloned().collect();
        rows.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.endpoint_id.cmp(&b.endpoint_id))
        });
        rows
    }
    pub fn get(&mut self, id: &str) -> Option<Observation> {
        self.expire();
        self.0.get(id).cloned()
    }
    pub fn remove(&mut self, id: &str) {
        self.0.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_expire_without_traffic_and_reset_on_restart() {
        let mut rows = Observations::default();
        rows.record("device".into(), None);
        rows.0.get_mut("device").unwrap().touched =
            Instant::now() - OBSERVATION_TTL - Duration::from_secs(1);
        assert!(rows.list().is_empty());
        rows.record("device".into(), None);
        assert!(Observations::default().list().is_empty());
    }
}
