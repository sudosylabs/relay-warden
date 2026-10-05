//! Shared per-endpoint throughput enforcement (Gate C).
//!
//! Contract:
//! - All connections of one endpoint share each directional allowance
//!   (`rx` = bytes/sec the relay accepts from the endpoint,
//!   `tx` = bytes/sec the relay delivers to it). Limits are per endpoint,
//!   never multiplied by connection count.
//! - `None` in either direction means unlimited (owner exemption). Approval,
//!   authentication, and (Gate D) quota still apply.
//! - Debt buckets: `consume` deducts exactly once per frame and may go
//!   negative; waiters sleep until the debt clears. Separate check
//!   (`wait`) never deducts, so retries, repeated polls, and flushes cannot
//!   double-charge.
//! - Policy changes clamp (`min(old fill, new max)`), never minting burst.
//!   Reconnects reuse the surviving limiter, so rapid reconnects or toggles
//!   cannot mint fresh burst. Idle limiter state is pruned after a retention
//!   window (documented tradeoff: a live-but-idle-beyond-retention endpoint
//!   restarts full).
//! - Buckets take an explicit `now: Instant` so unit tests advance time
//!   deterministically; production passes `Instant::now()`.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::Waker,
    time::{Duration, Instant},
};

/// Ordinary-endpoint defaults. `None` = not configured (see resolve rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Defaults {
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
}

/// Effective per-endpoint limit. Directions are independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitConfig {
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub burst_bytes: u64,
}

/// Resolve the effective config for a policy record.
///
/// - `unlimited` -> no caps (owner exemption; approval still required).
/// - `custom` -> the record's directional overrides.
/// - `default` -> operator defaults; when defaults are not configured the
///   endpoint is currently unshaped (production startup refuses to start in
///   that state via `require_default_limits`, so this is a test/dev path).
pub fn resolve_effective(
    record: Option<&crate::policy::EndpointPolicy>,
    defaults: &Defaults,
) -> LimitConfig {
    use crate::policy::SpeedPolicy;
    let burst_default = |rx: Option<u64>, tx: Option<u64>| -> u64 {
        let top = rx.or(tx).unwrap_or(65_536).max(tx.or(rx).unwrap_or(0));
        (top / 10).clamp(4_096, 1_048_576)
    };
    match record {
        None => LimitConfig {
            rx_bps: None,
            tx_bps: None,
            burst_bytes: 65_536,
        },
        Some(r) => {
            let burst = r.burst_bytes.map(|b| b as u64).unwrap_or_else(|| {
                burst_default(
                    match r.speed_policy {
                        SpeedPolicy::Custom => r.custom_rx_bps.map(|b| b as u64),
                        SpeedPolicy::Default => defaults.rx_bps,
                        SpeedPolicy::Unlimited => None,
                    },
                    match r.speed_policy {
                        SpeedPolicy::Custom => r.custom_tx_bps.map(|b| b as u64),
                        SpeedPolicy::Default => defaults.tx_bps,
                        SpeedPolicy::Unlimited => None,
                    },
                )
            });
            match r.speed_policy {
                SpeedPolicy::Unlimited => LimitConfig {
                    rx_bps: None,
                    tx_bps: None,
                    burst_bytes: burst,
                },
                SpeedPolicy::Custom => LimitConfig {
                    rx_bps: r.custom_rx_bps.map(|b| b as u64),
                    tx_bps: r.custom_tx_bps.map(|b| b as u64),
                    burst_bytes: burst,
                },
                SpeedPolicy::Default => LimitConfig {
                    rx_bps: defaults.rx_bps,
                    tx_bps: defaults.tx_bps,
                    burst_bytes: burst,
                },
            }
        }
    }
}

/// Debt token bucket. Always deducts on `consume`; overdraw yields a wait.
/// Never deducts on `wait`. All math advances lazily from `now`.
#[derive(Debug)]
pub struct Bucket {
    rate_bps: f64,
    max: f64,
    fill: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(rate_bps: u64, max_bytes: u64, now: Instant) -> Self {
        assert!(rate_bps > 0, "rate must be positive");
        assert!(max_bytes > 0, "burst must be positive");
        Self {
            rate_bps: rate_bps as f64,
            max: max_bytes as f64,
            fill: max_bytes as f64,
            last: now,
        }
    }

    /// Start empty: used when a cap appears on an already-known limiter
    /// (unlimited -> limited transition). Starting full would mint a burst
    /// on every such toggle; earning it back is the conservative choice.
    /// Fresh limiters (first connect) still start full.
    pub fn empty(rate_bps: u64, max_bytes: u64, now: Instant) -> Self {
        let mut b = Self::new(rate_bps, max_bytes, now);
        b.fill = 0.0;
        b
    }

    fn update(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        if dt > 0.0 {
            self.fill = (self.fill + dt * self.rate_bps).min(self.max);
            self.last = now;
        }
    }

    /// Reconfigure rates, clamping the balance down (never minting).
    pub fn set_config(&mut self, rate_bps: u64, max_bytes: u64, now: Instant) {
        assert!(rate_bps > 0 && max_bytes > 0);
        self.update(now);
        self.rate_bps = rate_bps as f64;
        self.max = max_bytes as f64;
        self.fill = self.fill.min(self.max);
    }

    /// Deduct `n` bytes exactly once. Returns the wait if overdrawn.
    pub fn consume(&mut self, n: usize, now: Instant) -> Option<Duration> {
        self.update(now);
        self.fill -= n as f64;
        // Saturate runaway debt (still far beyond any legitimate frame).
        let floor = -(self.max * 32.0 + 16_777_216.0);
        if self.fill < floor {
            self.fill = floor;
        }
        if self.fill <= 0.0 {
            Some(self.until_positive())
        } else {
            None
        }
    }

    /// Peek without deducting. Returns the wait if currently overdrawn.
    pub fn wait(&mut self, now: Instant) -> Option<Duration> {
        self.update(now);
        if self.fill <= 0.0 {
            Some(self.until_positive())
        } else {
            None
        }
    }

    fn until_positive(&self) -> Duration {
        let missing = -self.fill + 1.0;
        Duration::from_secs_f64((missing / self.rate_bps).max(0.0))
    }

    #[cfg(test)]
    fn fill(&self) -> f64 {
        self.fill
    }
}

/// Shared limiter for one endpoint (both directions + counters).
#[derive(Debug)]
pub struct EndpointLimiter {
    rx: Mutex<Option<Bucket>>,
    tx: Mutex<Option<Bucket>>,
    config: Mutex<LimitConfig>,
    revision: Mutex<i64>,
    last_used: Mutex<Instant>,
    waiters: Mutex<HashMap<u64, Waker>>,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub throttled_bytes: AtomicU64,
    pub throttled_wait_ms: AtomicU64,
}

impl EndpointLimiter {
    fn new(cfg: LimitConfig, revision: i64, now: Instant) -> Self {
        Self {
            rx: Mutex::new(cfg.rx_bps.map(|r| Bucket::new(r, cfg.burst_bytes, now))),
            tx: Mutex::new(cfg.tx_bps.map(|r| Bucket::new(r, cfg.burst_bytes, now))),
            config: Mutex::new(cfg),
            revision: Mutex::new(revision),
            last_used: Mutex::new(now),
            waiters: Mutex::new(HashMap::new()),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            throttled_bytes: AtomicU64::new(0),
            throttled_wait_ms: AtomicU64::new(0),
        }
    }

    /// Apply a new config, preserving balances (clamped, never minted).
    /// Returns true if the config changed.
    fn apply(&self, cfg: LimitConfig, revision: i64, now: Instant) -> bool {
        {
            let mut rev = self.revision.lock().expect("lock");
            if revision <= *rev && *self.config.lock().expect("lock") == cfg {
                return false;
            }
            *rev = revision.max(*rev);
        }
        let mut config = self.config.lock().expect("lock");
        if *config == cfg {
            return false;
        }
        // Reconcile buckets with the new config, preserving fill.
        let mut rx = self.rx.lock().expect("lock");
        let mut tx = self.tx.lock().expect("lock");
        match (cfg.rx_bps, rx.as_mut()) {
            (Some(rate), Some(b)) => b.set_config(rate, cfg.burst_bytes, now),
            (Some(rate), None) => *rx = Some(Bucket::empty(rate, cfg.burst_bytes, now)),
            (None, _) => *rx = None,
        }
        match (cfg.tx_bps, tx.as_mut()) {
            (Some(rate), Some(b)) => b.set_config(rate, cfg.burst_bytes, now),
            (Some(rate), None) => *tx = Some(Bucket::empty(rate, cfg.burst_bytes, now)),
            (None, _) => *tx = None,
        }
        *config = cfg;
        drop(config);
        drop(rx);
        drop(tx);
        self.poke();
        true
    }

    fn touch(&self, now: Instant) {
        *self.last_used.lock().expect("lock") = now;
    }

    pub fn last_used(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*self.last_used.lock().expect("lock"))
    }

    pub fn config(&self) -> LimitConfig {
        *self.config.lock().expect("lock")
    }

    /// Register a waiter's waker for policy-change/shutdown wakes.
    pub fn subscribe(&self, id: u64, w: Waker) {
        self.waiters.lock().expect("lock").insert(id, w);
    }

    pub fn unsubscribe(&self, id: u64) {
        self.waiters.lock().expect("lock").remove(&id);
    }

    /// Wake all waiters (policy change / shutdown).
    pub fn poke(&self) {
        let waiters: Vec<Waker> = self
            .waiters
            .lock()
            .expect("lock")
            .values()
            .cloned()
            .collect();
        for w in waiters {
            w.wake();
        }
    }

    pub fn check_rx(&self, now: Instant) -> Option<Duration> {
        self.touch(now);
        self.rx
            .lock()
            .expect("lock")
            .as_mut()
            .and_then(|b| b.wait(now))
    }

    pub fn consume_rx(&self, n: usize, now: Instant) -> Option<Duration> {
        self.touch(now);
        self.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.rx
            .lock()
            .expect("lock")
            .as_mut()
            .and_then(|b| b.consume(n, now))
    }

    pub fn check_tx(&self, now: Instant) -> Option<Duration> {
        self.touch(now);
        self.tx
            .lock()
            .expect("lock")
            .as_mut()
            .and_then(|b| b.wait(now))
    }

    pub fn consume_tx(&self, n: usize, now: Instant) -> Option<Duration> {
        self.touch(now);
        self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.tx
            .lock()
            .expect("lock")
            .as_mut()
            .and_then(|b| b.consume(n, now))
    }

    pub fn record_throttled(&self, bytes: usize, waited_ms: u64) {
        self.throttled_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.throttled_wait_ms
            .fetch_add(waited_ms, Ordering::Relaxed);
    }
}

/// Registry of per-endpoint limiters.
#[derive(Debug, Default)]
pub struct LimiterMap {
    inner: Mutex<HashMap<String, Arc<EndpointLimiter>>>,
}

impl LimiterMap {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Get the shared limiter, creating full (or updating in place on config
    /// change without minting). Same revision + config is a no-op.
    pub fn get_or_create(
        &self,
        endpoint_id: &str,
        record: Option<&crate::policy::EndpointPolicy>,
        defaults: &Defaults,
        now: Instant,
    ) -> Arc<EndpointLimiter> {
        let cfg = resolve_effective(record, defaults);
        let revision = record.map(|r| r.revision).unwrap_or(0);
        let mut map = self.inner.lock().expect("lock");
        if let Some(lim) = map.get(endpoint_id) {
            lim.apply(cfg, revision, now);
            lim.touch(now);
            return lim.clone();
        }
        let lim = Arc::new(EndpointLimiter::new(cfg, revision, now));
        map.insert(endpoint_id.to_string(), lim.clone());
        lim
    }

    /// Push a policy change into the live limiter (no reconnect needed).
    /// Unknown endpoints (no limiter yet) are ignored: limiters are only
    /// created on connect, bounding memory.
    pub fn apply_record(
        &self,
        record: &crate::policy::EndpointPolicy,
        defaults: &Defaults,
        now: Instant,
    ) {
        let cfg = resolve_effective(Some(record), defaults);
        let map = self.inner.lock().expect("lock");
        if let Some(lim) = map.get(&record.endpoint_id) {
            lim.apply(cfg, record.revision, now);
        }
    }

    /// Re-apply all known records (e.g. after a defaults change).
    pub fn apply_all(
        &self,
        records: &[crate::policy::EndpointPolicy],
        defaults: &Defaults,
        now: Instant,
    ) {
        for r in records {
            self.apply_record(r, defaults, now);
        }
    }

    /// Drop limiters idle longer than `max_idle`. Returns removal count.
    pub fn prune_older_than(&self, max_idle: Duration, now: Instant) -> usize {
        let mut map = self.inner.lock().expect("lock");
        let before = map.len();
        map.retain(|_, lim| lim.last_used(now) <= max_idle);
        before - map.len()
    }

    pub fn wake_all(&self) {
        let map = self.inner.lock().expect("lock");
        for lim in map.values() {
            lim.poke();
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().expect("lock").is_empty()
    }

    /// Snapshot of all limiter stats for observability.
    pub fn snapshot(&self) -> Vec<(String, EndpointStats)> {
        let map = self.inner.lock().expect("lock");
        map.iter()
            .map(|(id, lim)| (id.clone(), lim.stats()))
            .collect()
    }

    #[allow(dead_code)]
    pub fn get(&self, endpoint_id: &str) -> Option<Arc<EndpointLimiter>> {
        self.inner.lock().expect("lock").get(endpoint_id).cloned()
    }
}

/// Per-endpoint stats snapshot for the admin API.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub throttled_bytes: u64,
    pub throttled_wait_ms: u64,
}

impl EndpointLimiter {
    pub fn stats(&self) -> EndpointStats {
        let cfg = self.config();
        EndpointStats {
            rx_bps: cfg.rx_bps,
            tx_bps: cfg.tx_bps,
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            throttled_bytes: self.throttled_bytes.load(Ordering::Relaxed),
            throttled_wait_ms: self.throttled_wait_ms.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn bucket_burst_then_debt_then_refill() {
        let start = t0();
        let mut b = Bucket::new(10_000, 20_000, start);
        // Within burst: allowed (fill stays positive).
        assert!(b.consume(19_999, start).is_none());
        // Exact drain hits zero, which reads as overdrawn (tiny wait).
        let tiny = b.consume(1, start).expect("wait");
        assert!(tiny < Duration::from_millis(50));
        // Debt: further frames wait; peeks agree without charging.
        let w1 = b.consume(5_000, start).expect("wait");
        assert_eq!(w1, b.wait(start).expect("wait"));
        assert_eq!(b.wait(start), b.wait(start));
        // Refill after enough time clears the debt.
        let later = start + Duration::from_secs(3);
        assert!(b.wait(later).is_none());
        assert!(b.consume(1_000, later).is_none());
    }

    #[test]
    fn bucket_oversize_frame_uses_debt_not_deadlock() {
        let start = t0();
        let mut b = Bucket::new(10_000, 1_000, start);
        // A frame larger than the burst is admitted once (debt), then waits.
        let w = b.consume(64_000, start).expect("wait");
        assert!(w > Duration::from_secs(5));
        assert!(b.wait(start + w + Duration::from_millis(50)).is_none());
    }

    #[test]
    fn bucket_reconfig_clamps_never_mints() {
        let start = t0();
        let mut b = Bucket::new(10_000, 10_000, start);
        assert!(b.consume(9_000, start).is_none());
        assert!((b.fill() - 1_000.0).abs() < 1.0);
        // Raising the burst must not mint: fill stays 1000.
        b.set_config(10_000, 100_000, start);
        assert!((b.fill() - 1_000.0).abs() < 1.0);
        // Lowering below fill clamps down.
        b.set_config(10_000, 500, start);
        assert!(b.fill() <= 500.0 + 1.0);
    }

    #[test]
    fn resolve_matrix() {
        use crate::policy::{EndpointPolicy, SpeedPolicy};
        let d = Defaults {
            rx_bps: Some(1_000),
            tx_bps: Some(2_000),
        };
        let mut rec = EndpointPolicy::new("id".into(), "l".into());
        // Default follows operator defaults.
        let c = resolve_effective(Some(&rec), &d);
        assert_eq!((c.rx_bps, c.tx_bps), (Some(1_000), Some(2_000)));
        // Custom overrides per direction.
        rec.speed_policy = SpeedPolicy::Custom;
        rec.custom_rx_bps = Some(100);
        let c = resolve_effective(Some(&rec), &d);
        assert_eq!((c.rx_bps, c.tx_bps), (Some(100), None));
        // Unlimited removes caps.
        rec.speed_policy = SpeedPolicy::Unlimited;
        rec.custom_rx_bps = None;
        let c = resolve_effective(Some(&rec), &d);
        assert_eq!((c.rx_bps, c.tx_bps), (None, None));
        // Missing defaults -> unshaped (startup gate covers production).
        let c = resolve_effective(
            Some(&EndpointPolicy::new("x".into(), "".into())),
            &Defaults::default(),
        );
        assert_eq!((c.rx_bps, c.tx_bps), (None, None));
    }

    #[test]
    fn limiter_reconnect_reuses_balances() {
        let start = t0();
        let map = LimiterMap::new();
        let d = Defaults {
            rx_bps: Some(10_000),
            tx_bps: Some(10_000),
        };
        let mut rec = crate::policy::EndpointPolicy::new("e".into(), "".into());
        rec.approved = true;
        let lim1 = map.get_or_create("e", Some(&rec), &d, start);
        // Drain most of the burst (burst = max(4096, rate/10) = 4096).
        assert!(lim1.consume_rx(3_500, start).is_none());
        // Reconnect (same revision/config) reuses the same limiter object.
        let lim2 = map.get_or_create("e", Some(&rec), &d, start);
        assert!(Arc::ptr_eq(&lim1, &lim2));
        // Still throttled: no fresh burst was minted.
        assert!(lim2.consume_rx(1_000, start).is_some());
    }

    #[test]
    fn limiter_toggle_cannot_mint_burst() {
        let start = t0();
        let map = LimiterMap::new();
        let d = Defaults {
            rx_bps: Some(10_000),
            tx_bps: Some(10_000),
        };
        let mut rec = crate::policy::EndpointPolicy::new("e".into(), "".into());
        rec.approved = true;
        let lim = map.get_or_create("e", Some(&rec), &d, start);
        assert!(lim.consume_rx(1_000, start).is_none());
        // Rapid toggle unlimited -> default: fill clamps, no refill.
        rec.speed_policy = crate::policy::SpeedPolicy::Unlimited;
        rec.revision += 1;
        map.apply_record(&rec, &d, start);
        rec.speed_policy = crate::policy::SpeedPolicy::Default;
        rec.revision += 1;
        map.apply_record(&rec, &d, start);
        // Balance is at most the small remainder, not a fresh burst.
        assert!(lim.consume_rx(1_000, start).is_some());
    }
}
