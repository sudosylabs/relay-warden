//! Bounded source-network admission and shared directional bandwidth buckets.
//! The socket peer is authoritative unless it is an explicitly trusted proxy.
use crate::limiter::{Bucket, EndpointLimiter, LimitConfig};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub ip_rx_bps: u64,
    pub ip_tx_bps: u64,
    pub prefix_rx_bps: u64,
    pub prefix_tx_bps: u64,
    pub global_rx_bps: u64,
    pub global_tx_bps: u64,
    pub ipv4_prefix: Option<u8>,
    pub ipv6_prefix: Option<u8>,
    pub ipv6_prefix_enabled: bool,
    pub attempts_per_second: u64,
    pub attempt_burst: u64,
    pub prefix_attempts_per_second: u64,
    pub prefix_attempt_burst: u64,
    pub global_attempts_per_second: u64,
    pub global_attempt_burst: u64,
    pub max_connections_per_ip: usize,
    pub max_connections_per_prefix: usize,
    pub max_entries: usize,
    pub trusted_proxies: Vec<IpAddr>,
}
impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ip_rx_bps: 1_000_000,
            ip_tx_bps: 1_000_000,
            prefix_rx_bps: 5_000_000,
            prefix_tx_bps: 5_000_000,
            global_rx_bps: 10_000_000,
            global_tx_bps: 10_000_000,
            ipv4_prefix: None,
            ipv6_prefix: Some(64),
            ipv6_prefix_enabled: true,
            attempts_per_second: 5,
            attempt_burst: 20,
            prefix_attempts_per_second: 20,
            prefix_attempt_burst: 80,
            global_attempts_per_second: 100,
            global_attempt_burst: 200,
            max_connections_per_ip: 64,
            max_connections_per_prefix: 256,
            max_entries: 16_384,
            trusted_proxies: Vec::new(),
        }
    }
}
impl NetworkConfig {
    pub fn validate(&self) -> Result<(), String> {
        for n in [
            self.ip_rx_bps,
            self.ip_tx_bps,
            self.prefix_rx_bps,
            self.prefix_tx_bps,
            self.global_rx_bps,
            self.global_tx_bps,
            self.attempts_per_second,
            self.attempt_burst,
            self.prefix_attempts_per_second,
            self.prefix_attempt_burst,
            self.global_attempts_per_second,
            self.global_attempt_burst,
        ] {
            if n == 0 || n > 100_000_000_000 {
                return Err("network rates and bursts must be 1..=100000000000".into());
            }
        }
        if self.max_entries < 2
            || self.max_entries > 1_000_000
            || self.max_connections_per_ip == 0
            || self.max_connections_per_prefix == 0
        {
            return Err(
                "network capacities must be positive; max_entries must be 2..=1000000".into(),
            );
        }
        if self.ipv4_prefix.is_some_and(|n| n == 0 || n > 32)
            || self.ipv6_prefix.is_some_and(|n| n == 0 || n > 128)
        {
            return Err("network prefixes must be IPv4 1..=32 or IPv6 1..=128".into());
        }
        Ok(())
    }
    fn trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|p| normalize(*p) == normalize(ip))
    }
    /// Walk X-Forwarded-For from the trusted socket peer toward the client.
    /// Never accept a claim sent directly by an untrusted peer.
    pub fn source_ip(
        &self,
        peer: IpAddr,
        headers: &http::HeaderMap,
    ) -> Result<IpAddr, &'static str> {
        let mut source = normalize(peer);
        if !self.trusted(source) {
            return Ok(source);
        }
        let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
        if values.len() != 1 {
            return Err("trusted proxy must supply one X-Forwarded-For header");
        }
        let value = values[0]
            .to_str()
            .map_err(|_| "invalid forwarded address")?;
        if value.len() > 1024 {
            return Err("forwarded address chain too long");
        }
        let chain: Vec<_> = value
            .split(',')
            .map(|s| s.trim().parse::<IpAddr>().map(normalize))
            .collect::<Result<_, _>>()
            .map_err(|_| "invalid forwarded address")?;
        if chain.is_empty() || chain.len() > 16 {
            return Err("invalid forwarded address chain");
        }
        for ip in chain.into_iter().rev() {
            if !self.trusted(source) {
                break;
            }
            source = ip;
        }
        Ok(source)
    }
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Key {
    Ip(IpAddr),
    Prefix(IpAddr, u8),
}
fn prefix(ip: IpAddr, cfg: &NetworkConfig) -> Option<Key> {
    match ip {
        IpAddr::V4(v) => cfg.ipv4_prefix.map(|n| {
            Key::Prefix(
                IpAddr::V4((u32::from(v) & (u32::MAX << (32 - n))).into()),
                n,
            )
        }),
        IpAddr::V6(v) if cfg.ipv6_prefix_enabled => cfg.ipv6_prefix.map(|n| {
            Key::Prefix(
                IpAddr::V6((u128::from(v) & (u128::MAX << (128 - n))).into()),
                n,
            )
        }),
        IpAddr::V6(_) => None,
    }
}
#[derive(Debug)]
struct Entry {
    bandwidth: Arc<EndpointLimiter>,
    attempts: Bucket,
    active: usize,
    last: Instant,
}
#[derive(Debug)]
struct State {
    entries: HashMap<Key, Entry>,
    attempts: Bucket,
}
#[derive(Debug)]
pub struct NetworkGuard {
    config: NetworkConfig,
    state: Mutex<State>,
    global: Arc<EndpointLimiter>,
    rejected: std::sync::atomic::AtomicU64,
}
pub struct ConnectionLease {
    guard: Arc<NetworkGuard>,
    keys: Vec<Key>,
    pub(crate) bandwidth: Vec<Arc<EndpointLimiter>>,
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        let mut state = self.guard.state.lock().expect("network state");
        for key in &self.keys {
            if let Some(e) = state.entries.get_mut(key) {
                e.active -= 1;
                e.last = Instant::now();
            }
        }
    }
}
fn bandwidth(rx: u64, tx: u64, now: Instant) -> Arc<EndpointLimiter> {
    Arc::new(EndpointLimiter::new(
        LimitConfig {
            rx_bps: Some(rx),
            tx_bps: Some(tx),
            burst_bytes: rx.max(tx).clamp(4096, 1_048_576),
        },
        0,
        now,
    ))
}
impl NetworkGuard {
    pub fn new(config: NetworkConfig, now: Instant) -> Result<Arc<Self>, String> {
        config.validate()?;
        Ok(Arc::new(Self {
            rejected: std::sync::atomic::AtomicU64::new(0),
            global: bandwidth(config.global_rx_bps, config.global_tx_bps, now),
            state: Mutex::new(State {
                entries: HashMap::new(),
                attempts: Bucket::new(
                    config.global_attempts_per_second,
                    config.global_attempt_burst,
                    now,
                ),
            }),
            config,
        }))
    }
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    pub fn summary(&self) -> serde_json::Value {
        let state = self.state.lock().expect("network state");
        serde_json::json!({"config": self.config, "tracked_sources": state.entries.len(), "rejected_total": self.rejected.load(std::sync::atomic::Ordering::Relaxed)})
    }
    pub(crate) fn global(&self) -> Arc<EndpointLimiter> {
        self.global.clone()
    }
    /// Reserve capacity before WebSocket upgrade/authentication. Rejections do
    /// not evict active buckets or refresh an attacker's allowance.
    pub fn admit(
        self: &Arc<Self>,
        ip: IpAddr,
        now: Instant,
    ) -> Result<ConnectionLease, &'static str> {
        let result = self.admit_inner(ip, now);
        if result.is_err() {
            self.rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    fn admit_inner(
        self: &Arc<Self>,
        ip: IpAddr,
        now: Instant,
    ) -> Result<ConnectionLease, &'static str> {
        let ip = normalize(ip);
        let mut keys = vec![Key::Ip(ip)];
        if let Some(p) = prefix(ip, &self.config) {
            keys.push(p);
        }
        let mut state = self.state.lock().expect("network state");
        if state.attempts.wait(now).is_some() {
            return Err("global connection attempt limit");
        }
        state.attempts.consume(1, now);
        let missing = keys
            .iter()
            .filter(|k| !state.entries.contains_key(k))
            .count();
        if state.entries.len() + missing > self.config.max_entries {
            state.entries.retain(|_, e| {
                // Only discard idle, fully replenished buckets. No fresh-burst
                // loophole from evicting debt, nor eviction of live entries.
                let cfg = e.bandwidth.config();
                let refill = cfg
                    .burst_bytes
                    .div_ceil(cfg.rx_bps.unwrap().min(cfg.tx_bps.unwrap()));
                e.active > 0
                    || now.saturating_duration_since(e.last)
                        < Duration::from_secs(
                            600.max(refill)
                                .max(
                                    self.config
                                        .attempt_burst
                                        .div_ceil(self.config.attempts_per_second),
                                )
                                .max(
                                    self.config
                                        .prefix_attempt_burst
                                        .div_ceil(self.config.prefix_attempts_per_second),
                                ),
                        )
                    || e.bandwidth.check_rx(now).is_some()
                    || e.bandwidth.check_tx(now).is_some()
            });
            let missing = keys
                .iter()
                .filter(|k| !state.entries.contains_key(k))
                .count();
            if state.entries.len() + missing > self.config.max_entries {
                return Err("network tracking capacity");
            }
        }
        let mut allowed = true;
        for key in &keys {
            let is_ip = matches!(key, Key::Ip(_));
            let e = state.entries.entry(*key).or_insert_with(|| Entry {
                bandwidth: bandwidth(
                    if is_ip {
                        self.config.ip_rx_bps
                    } else {
                        self.config.prefix_rx_bps
                    },
                    if is_ip {
                        self.config.ip_tx_bps
                    } else {
                        self.config.prefix_tx_bps
                    },
                    now,
                ),
                attempts: Bucket::new(
                    if is_ip {
                        self.config.attempts_per_second
                    } else {
                        self.config.prefix_attempts_per_second
                    },
                    if is_ip {
                        self.config.attempt_burst
                    } else {
                        self.config.prefix_attempt_burst
                    },
                    now,
                ),
                active: 0,
                last: now,
            });
            e.last = now;
            if e.attempts.wait(now).is_some() {
                allowed = false;
            } else {
                e.attempts.consume(1, now);
            }
            if e.active
                >= if is_ip {
                    self.config.max_connections_per_ip
                } else {
                    self.config.max_connections_per_prefix
                }
            {
                allowed = false;
            }
        }
        if !allowed {
            return Err("source connection limit");
        }
        let mut buckets = Vec::new();
        for key in &keys {
            let e = state.entries.get_mut(key).expect("entry");
            e.active += 1;
            buckets.push(e.bandwidth.clone());
        }
        Ok(ConnectionLease {
            guard: self.clone(),
            keys,
            bandwidth: buckets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    #[test]
    fn source_headers_require_explicit_proxy_trust() {
        let mut cfg = NetworkConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.0.2.1, 198.51.100.2".parse().unwrap(),
        );
        assert_eq!(
            cfg.source_ip(ip("203.0.113.3"), &headers).unwrap(),
            ip("203.0.113.3")
        );
        cfg.trusted_proxies = vec![ip("203.0.113.3")];
        assert_eq!(
            cfg.source_ip(ip("203.0.113.3"), &headers).unwrap(),
            ip("198.51.100.2")
        );
        cfg.trusted_proxies.push(ip("198.51.100.2"));
        assert_eq!(
            cfg.source_ip(ip("203.0.113.3"), &headers).unwrap(),
            ip("192.0.2.1")
        );
        headers.insert("x-forwarded-for", "invalid".parse().unwrap());
        assert!(cfg.source_ip(ip("203.0.113.3"), &headers).is_err());
        headers.clear();
        assert!(cfg.source_ip(ip("203.0.113.3"), &headers).is_err());
        assert_eq!(
            cfg.source_ip(ip("::ffff:192.0.2.1"), &headers).unwrap(),
            ip("192.0.2.1")
        );
    }
    #[test]
    fn independent_ips_share_only_their_prefix_and_global_buckets() {
        let now = Instant::now();
        let guard = NetworkGuard::new(NetworkConfig::default(), now).unwrap();
        let a = guard.admit(ip("2001:db8::1"), now).unwrap();
        let b = guard.admit(ip("2001:db8::2"), now).unwrap();
        let c = guard.admit(ip("2001:db8:0:1::1"), now).unwrap();
        assert!(!Arc::ptr_eq(&a.bandwidth[0], &b.bandwidth[0]));
        assert!(Arc::ptr_eq(&a.bandwidth[1], &b.bandwidth[1]));
        assert!(!Arc::ptr_eq(&a.bandwidth[1], &c.bandwidth[1]));
        let cfg = a.bandwidth[1].config();
        a.bandwidth[1].consume_rx(cfg.burst_bytes as usize + 100, now);
        assert!(b.bandwidth[1].check_rx(now).is_some());
        assert!(b.bandwidth[1].check_tx(now).is_none());
        assert!(c.bandwidth[1].check_rx(now).is_none());
        guard
            .global
            .consume_tx(guard.global.config().burst_bytes as usize + 100, now);
        assert!(guard.global.check_tx(now).is_some());
    }
    #[test]
    fn reconnects_share_bandwidth_and_do_not_mint_burst() {
        let now = Instant::now();
        let guard = NetworkGuard::new(NetworkConfig::default(), now).unwrap();
        let a = guard.admit(ip("192.0.2.1"), now).unwrap();
        a.bandwidth[0].consume_rx(1_100_000, now);
        drop(a);
        let b = guard.admit(ip("::ffff:192.0.2.1"), now).unwrap();
        assert!(b.bandwidth[0].check_rx(now).is_some());
    }
    #[test]
    fn source_and_prefix_capacity_are_released_on_drop() {
        let now = Instant::now();
        let cfg = NetworkConfig {
            max_connections_per_ip: 1,
            max_connections_per_prefix: 2,
            ..Default::default()
        };
        let guard = NetworkGuard::new(cfg, now).unwrap();
        let a = guard.admit(ip("2001:db8::1"), now).unwrap();
        assert!(guard.admit(ip("2001:db8::1"), now).is_err());
        let b = guard.admit(ip("2001:db8::2"), now).unwrap();
        assert!(guard.admit(ip("2001:db8::3"), now).is_err());
        drop(a);
        assert!(guard.admit(ip("2001:db8::3"), now).is_ok());
        drop(b);
    }
    #[test]
    fn attempt_limits_refill_without_accumulating_rejected_debt() {
        let now = Instant::now();
        let cfg = NetworkConfig {
            attempts_per_second: 1,
            attempt_burst: 2,
            ..Default::default()
        };
        let guard = NetworkGuard::new(cfg, now).unwrap();
        for _ in 0..2 {
            drop(guard.admit(ip("192.0.2.1"), now).unwrap());
        }
        for _ in 0..100 {
            assert!(guard.admit(ip("192.0.2.1"), now).is_err());
        }
        assert!(guard
            .admit(ip("192.0.2.1"), now + Duration::from_secs(1))
            .is_ok());
        let cfg = NetworkConfig {
            global_attempt_burst: 1,
            global_attempts_per_second: 1,
            ..Default::default()
        };
        let guard = NetworkGuard::new(cfg, now).unwrap();
        drop(guard.admit(ip("192.0.2.1"), now).unwrap());
        assert!(guard.admit(ip("192.0.2.2"), now).is_err());
        assert!(guard
            .admit(ip("192.0.2.2"), now + Duration::from_secs(1))
            .is_ok());
    }
    #[test]
    fn tracking_is_bounded_and_does_not_evict_live_or_recent_entries() {
        let now = Instant::now();
        let guard = NetworkGuard::new(
            NetworkConfig {
                max_entries: 2,
                ..Default::default()
            },
            now,
        )
        .unwrap();
        let a = guard.admit(ip("192.0.2.1"), now).unwrap();
        drop(guard.admit(ip("192.0.2.2"), now).unwrap());
        assert!(guard.admit(ip("192.0.2.3"), now).is_err());
        assert!(guard
            .admit(ip("192.0.2.3"), now + Duration::from_secs(601))
            .is_ok());
        assert_eq!(guard.state.lock().unwrap().entries.len(), 2);
        drop(a);
    }
    #[test]
    fn prefix_configuration_and_validation() {
        let mut cfg = NetworkConfig::default();
        assert!(prefix(ip("192.0.2.1"), &cfg).is_none());
        cfg.ipv4_prefix = Some(24);
        assert_eq!(
            prefix(ip("192.0.2.1"), &cfg),
            prefix(ip("192.0.2.99"), &cfg)
        );
        cfg.ipv6_prefix = None;
        assert!(prefix(ip("2001:db8::1"), &cfg).is_none());
        let disabled: NetworkConfig = toml::from_str("ipv6_prefix_enabled = false").unwrap();
        assert!(prefix(ip("2001:db8::1"), &disabled).is_none());
        cfg.ipv4_prefix = Some(33);
        assert!(cfg.validate().is_err());
        cfg.ipv4_prefix = Some(0);
        assert!(cfg.validate().is_err());
        cfg.ipv4_prefix = None;
        cfg.max_entries = 0;
        assert!(cfg.validate().is_err());
    }
}
