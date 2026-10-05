//! Shared monthly outbound budget (Gate D).
//!
//! Accounting model (see design note in README):
//! - The enforced unit is *charged bytes*: payload bytes plus a configured
//!   overhead allowance. This is intentionally conservative versus true wire
//!   bytes (TLS, retransmits, other services) and is NOT an Oracle billing
//!   meter. The UI states the unit and the bounded uncertainty.
//! - Charging happens at chunk *grant* time (before bytes enter the send
//!   pipeline), never refunded except for lease remainders proven unspent
//!   (returned on clean connection close). Crash/restart therefore
//!   over-counts rather than under-counts: fail-closed.
//! - Effective cutoff = budget - headroom. Grants enforce
//!   `charged + want <= cutoff` under the single quota actor, which is the
//!   one serialization point for concurrent traffic.
//! - Exhaustion is persisted *before* denial, disconnects every relay
//!   connection (including owner endpoints), and denies new admissions via a
//!   shared flag read on the admission hot path (no SQLite there).
//! - Periods are UTC calendar months (`YYYY-MM`). Only forward transitions
//!   create a new ledger; a backward clock never reopens an older period or
//!   clears exhaustion. Month changes are atomic with grants (same actor).
//! - Only the relay traffic path stops. Admin, the shared proxy, and other
//!   services keep running. Ordinary endpoint edits never touch the ledger.

use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, SystemTime},
};

use tokio::sync::{mpsc, oneshot};

use crate::{policy::PolicyManager, store::Store};

/// UTC month clock. Injected so tests advance time deterministically.
pub trait Clock: Send + Sync + Debug {
    fn now(&self) -> SystemTime;
    fn month(&self) -> String {
        month_of(self.now())
    }
}

/// Production clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Test clock.
#[derive(Debug)]
pub struct ManualClock {
    t: RwLock<SystemTime>,
}

impl ManualClock {
    pub fn new(t: SystemTime) -> Self {
        Self { t: RwLock::new(t) }
    }

    pub fn set(&self, t: SystemTime) {
        *self.t.write().expect("lock") = t;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.t.read().expect("lock")
    }
}

pub fn month_of(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%Y-%m").to_string()
}

pub fn month_start(month: &str) -> Option<SystemTime> {
    let (y, m) = month.split_once('-')?;
    let dt = chrono::NaiveDate::from_ymd_opt(y.parse().ok()?, m.parse().ok()?, 1)?
        .and_hms_opt(0, 0, 0)?
        .and_utc();
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(dt.timestamp().max(0) as u64))
}

/// Quota configuration (from settings; operator-chosen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaConfig {
    /// Nominal monthly budget in bytes. `None` = gating disabled (dev/tests).
    pub budget_bytes: Option<u64>,
    pub headroom_bytes: u64,
    pub overhead_pct: u64,
    pub chunk_bytes: u64,
    /// Optional webhook URL for threshold/exhaustion alerts. Disabled when
    /// unset. Failed delivery is recorded, never retried blindly, and never
    /// affects enforcement.
    pub alert_webhook_url: Option<String>,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            budget_bytes: None,
            headroom_bytes: 1_000_000_000,
            overhead_pct: 10,
            chunk_bytes: 32_768,
            alert_webhook_url: None,
        }
    }
}

impl QuotaConfig {
    pub fn from_settings(v: &serde_json::Value) -> Self {
        let get = |k: &str| v.get(k).and_then(|x| x.as_i64()).map(|n| n as u64);
        let url = v
            .get("alert_webhook_url")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            budget_bytes: get("quota_budget_bytes"),
            headroom_bytes: get("quota_headroom_bytes").unwrap_or(1_000_000_000),
            overhead_pct: get("quota_overhead_pct").unwrap_or(10),
            chunk_bytes: get("quota_chunk_bytes")
                .unwrap_or(32_768)
                .clamp(1_024, 1_048_576),
            alert_webhook_url: url,
        }
    }

    /// Earlier cutoff the gate actually enforces (nominal minus headroom).
    pub fn cutoff(&self) -> Option<u64> {
        self.budget_bytes
            .map(|b| b.saturating_sub(self.headroom_bytes))
    }

    pub fn validate_patch(&self) -> Result<(), String> {
        if self.overhead_pct > 100 {
            return Err("quota_overhead_pct must be 0..=100".into());
        }
        if !(1_024..=1_048_576).contains(&self.chunk_bytes) {
            return Err("quota_chunk_bytes must be 1024..=1048576".into());
        }
        if let Some(url) = &self.alert_webhook_url {
            if url.len() > 512 || !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err("alert_webhook_url must be an http(s) URL <= 512 chars".into());
            }
        }
        Ok(())
    }
}

/// Conservative charged bytes for a payload: payload + overhead allowance.
/// Saturates instead of overflowing (a saturating charge always denies, since
/// no cutoff can contain it).
pub fn charged_for(payload_bytes: usize, overhead_pct: u64) -> u64 {
    let n = payload_bytes as u128;
    let total = n + (n * overhead_pct as u128).div_ceil(100);
    total.min(u64::MAX as u128) as u64
}

/// Restart-safe seed: durable flags imply their alerts already fired.
fn seed_fired(row: &crate::store::QuotaRow) -> std::collections::HashSet<(String, String)> {
    let mut set = std::collections::HashSet::new();
    if row.warn75 {
        set.insert((row.period.clone(), "warning_75".to_string()));
    }
    if row.warn90 {
        set.insert((row.period.clone(), "warning_90".to_string()));
    }
    if row.exhausted {
        set.insert((row.period.clone(), "exhausted".to_string()));
    }
    set
}

#[derive(Debug)]
enum QuotaMsg {
    Acquire {
        want: u64,
        reply: oneshot::Sender<AcquireReply>,
    },
    /// Proven-unspent lease remainder (clean connection close only).
    Return {
        bytes: u64,
    },
    /// Re-read settings + re-evaluate (budget change, explicit refresh).
    Refresh {
        reply: oneshot::Sender<()>,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum AcquireReply {
    Granted { bytes: u64, generation: u64 },
    Denied,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeliveryStatus {
    pub at: String,
    pub kind: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug)]
struct Shared {
    store: Arc<Store>,
    policy: Arc<PolicyManager>,
    clients: RwLock<Option<iroh_relay::server::clients::Clients>>,
    clock: Arc<dyn Clock>,
    cfg: RwLock<QuotaConfig>,
    exhausted: Arc<AtomicBool>,
    generation: AtomicU64,
    /// Actor's active ledger period (forward-only; source of truth for
    /// reporting — the wall clock may move backward).
    active_period: RwLock<String>,
    /// Fired alert kinds for the active period: (period, kind). Seeded from
    /// the durable warn/exhausted flags; each kind delivers at most once per
    /// period. Delivery failure never re-arms (operator sees last_delivery).
    fired: RwLock<std::collections::HashSet<(String, String)>>,
    last_delivery: RwLock<Option<DeliveryStatus>>,
    http: reqwest::Client,
}

/// Adapter-side handle: sync fast path + chunk requests to the actor.
#[derive(Debug, Clone)]
pub struct QuotaClient {
    shared: Arc<Shared>,
    tx: mpsc::Sender<QuotaMsg>,
}

impl QuotaClient {
    pub fn exhausted(&self) -> bool {
        self.shared.exhausted.load(Ordering::Relaxed)
    }

    pub fn generation(&self) -> u64 {
        self.shared.generation.load(Ordering::Relaxed)
    }

    fn cfg(&self) -> QuotaConfig {
        self.shared.cfg.read().expect("lock").clone()
    }

    pub fn chunk_bytes(&self) -> u64 {
        self.cfg().chunk_bytes
    }

    pub fn charge_for(&self, payload_bytes: usize) -> u64 {
        charged_for(payload_bytes, self.cfg().overhead_pct)
    }

    /// Request one chunk. `None` means the request channel is momentarily
    /// full (the actor drains fast); the adapter folds this into its wait
    /// loop and retries shortly.
    pub fn try_acquire(&self) -> Option<oneshot::Receiver<AcquireReply>> {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(QuotaMsg::Acquire {
            want: self.chunk_bytes(),
            reply: tx,
        }) {
            Ok(()) => Some(rx),
            Err(_) => None,
        }
    }

    /// Hand back a proven-unspent remainder. Best effort: if the channel is
    /// full or the actor is gone, the bytes stay charged (conservative).
    pub fn return_unused(&self, bytes: u64) {
        if bytes > 0 {
            let _ = self.tx.try_send(QuotaMsg::Return { bytes });
        }
    }
}

/// Quota manager: owns the actor that serializes grants against the ledger.
#[derive(Debug)]
pub struct QuotaManager {
    shared: Arc<Shared>,
    tx: mpsc::Sender<QuotaMsg>,
    #[allow(dead_code)]
    task: n0_future::task::AbortOnDropHandle<()>,
}

impl QuotaManager {
    pub async fn open(
        store: Arc<Store>,
        policy: Arc<PolicyManager>,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, String> {
        let (settings, _) = store.get_settings().await?;
        let cfg = QuotaConfig::from_settings(&settings);
        cfg.validate_patch()?;
        let month = clock.month();
        let row = store.open_period(&month).await?;
        // Derive exhaustion from the ledger itself: a crash between the
        // in-memory flag and a prior persist must not reopen the relay.
        // Persisted before any listener starts (open precedes serve).
        let mut exhausted_now = row.exhausted;
        if !exhausted_now && cfg.cutoff().is_some_and(|c| row.charged_bytes >= c) {
            store.set_exhausted(&month, true).await;
            exhausted_now = true;
        }
        // One shared cell: admission and the actor observe the same flag.
        let exhausted = Arc::new(AtomicBool::new(exhausted_now));
        policy.set_quota_exhausted(Some(exhausted.clone()));
        let shared = Arc::new(Shared {
            store,
            policy,
            clients: RwLock::new(None),
            clock,
            cfg: RwLock::new(cfg),
            exhausted,
            generation: AtomicU64::new(0),
            active_period: RwLock::new(month.clone()),
            fired: RwLock::new(seed_fired(&row)),
            last_delivery: RwLock::new(None),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        });
        let (tx, rx) = mpsc::channel(1024);
        let actor_shared = shared.clone();
        let task = tokio::spawn(async move {
            run_actor(actor_shared, rx, row.period, row.charged_bytes).await;
        });
        Ok(Arc::new(Self {
            shared,
            tx,
            task: n0_future::task::AbortOnDropHandle::new(task),
        }))
    }

    pub fn set_clients(&self, clients: iroh_relay::server::clients::Clients) {
        *self.shared.clients.write().expect("lock") = Some(clients);
    }

    pub fn client(&self) -> QuotaClient {
        QuotaClient {
            shared: self.shared.clone(),
            tx: self.tx.clone(),
        }
    }

    pub fn exhausted(&self) -> bool {
        self.shared.exhausted.load(Ordering::Relaxed)
    }

    /// Round-trip through the actor: re-read settings, roll forward the
    /// period if needed, re-evaluate exhaustion. Deterministic sync point.
    pub async fn refresh(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(QuotaMsg::Refresh { reply: tx }).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Direct grant for tests/synthetic accounting (same serialization).
    pub async fn acquire(&self, want: u64) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(QuotaMsg::Acquire { want, reply: tx })
            .await
            .is_err()
        {
            return false;
        }
        matches!(rx.await, Ok(AcquireReply::Granted { .. }))
    }

    /// Clean shutdown of the ledger actor.
    pub async fn shutdown(&self) {
        let _ = self.tx.send(QuotaMsg::Shutdown).await;
    }

    pub async fn usage(&self) -> Result<serde_json::Value, String> {
        let cfg = self.shared.cfg.read().expect("lock").clone();
        // Report the actor's ledger period, not the wall clock: a backward
        // clock must not resurrect an older period's row in the UI.
        let period = self.shared.active_period.read().expect("lock").clone();
        let row = self.shared.store.read_period(&period).await?;
        let cutoff = cfg.cutoff().unwrap_or(u64::MAX);
        Ok(serde_json::json!({
            "implemented": true,
            "period": row.period,
            "budget_bytes": cfg.budget_bytes,
            "headroom_bytes": cfg.headroom_bytes,
            "effective_cutoff_bytes": cfg.cutoff(),
            "charged_bytes": row.charged_bytes,
            "available_bytes": cutoff.saturating_sub(row.charged_bytes),
            "exhausted": row.exhausted,
            "warnings": {"w75": row.warn75, "w90": row.warn90},
            "overhead_pct": cfg.overhead_pct,
            "chunk_bytes": cfg.chunk_bytes,
            "alerts": {
                "webhook_configured": cfg.alert_webhook_url.is_some(),
                "last_delivery": self.shared.last_delivery.read().expect("lock").clone(),
            },
            "uncertainty_note": "Charged bytes are relay payload + overhead allowance counted at send admission, not Oracle billable bytes. In-flight kernel/proxy bytes admitted before exhaustion cannot be recalled; bound ~= connections x (chunk + max frame).",
        }))
    }
}

struct PeriodState {
    period: String,
    charged: u64,
}

async fn run_actor(
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<QuotaMsg>,
    period: String,
    charged: u64,
) {
    let mut st = PeriodState { period, charged };
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    QuotaMsg::Acquire { want, reply } => {
                        let granted = grant(&shared, &mut st, want).await;
                        let _ = reply.send(if granted {
                            AcquireReply::Granted { bytes: want, generation: shared.generation.load(Ordering::Relaxed) }
                        } else {
                            AcquireReply::Denied
                        });
                    }
                    QuotaMsg::Return { bytes } => {
                        // Mirror follows the commit: on storage failure the
                        // return is dropped and the bytes stay charged
                        // (fail-closed, conservative).
                        if shared.store.add_charged(&st.period, -(bytes as i64)).await.is_ok() {
                            st.charged = st.charged.saturating_sub(bytes);
                        }
                    }
                    QuotaMsg::Refresh { reply } => {
                        refresh_config(&shared).await;
                        roll_forward(&shared, &mut st).await;
                        reevaluate(&shared, &mut st).await;
                        let _ = reply.send(());
                    }
                    QuotaMsg::Shutdown => break,
                }
            }
            _ = tick.tick() => {
                // Idle rollover: no traffic at a month boundary still flips
                // the ledger (and clears stale exhaustion) without traffic.
                roll_forward(&shared, &mut st).await;
            }
        }
    }
}

/// Advance to the clock's month only. A backward clock never reopens older
/// periods and never clears exhaustion.
async fn roll_forward(shared: &Arc<Shared>, st: &mut PeriodState) {
    let now_month = shared.clock.month();
    if now_month > st.period {
        if let Ok(row) = shared.store.open_period(&now_month).await {
            st.period = row.period.clone();
            st.charged = row.charged_bytes;
            *shared.active_period.write().expect("lock") = row.period.clone();
            // Fresh period, fresh dedup (durable flags seed restarts).
            *shared.fired.write().expect("lock") = seed_fired(&row);
            shared.exhausted.store(row.exhausted, Ordering::Relaxed);
            shared.generation.fetch_add(1, Ordering::Relaxed);
            // Leases granted under the old generation are discarded by
            // adapters (their charge stays in the old period: conservative).
            tracing::info!(period = %st.period, "quota period rolled forward");
        }
    }
}

async fn refresh_config(shared: &Arc<Shared>) {
    if let Ok((settings, _)) = shared.store.get_settings().await {
        let cfg = QuotaConfig::from_settings(&settings);
        if cfg.validate_patch().is_ok() {
            *shared.cfg.write().expect("lock") = cfg;
        }
    }
}

/// Re-evaluate exhaustion after a config change: a raised budget honestly
/// reopens (audited by the caller), a lowered one exhausts immediately.
async fn reevaluate(shared: &Arc<Shared>, st: &mut PeriodState) {
    let cutoff = shared
        .cfg
        .read()
        .expect("lock")
        .cutoff()
        .unwrap_or(u64::MAX);
    if st.charged >= cutoff {
        if !shared.exhausted.load(Ordering::Relaxed) {
            exhaust(shared, st).await;
        }
    } else if shared.exhausted.load(Ordering::Relaxed) {
        // Explicit re-budget above usage reopens; ordinary edits never reach here.
        shared.exhausted.store(false, Ordering::Relaxed);
        shared.store.set_exhausted(&st.period, false).await;
        tracing::info!("quota reopened by re-budget");
    }
}

/// Single serialization point for every grant.
async fn grant(shared: &Arc<Shared>, st: &mut PeriodState, want: u64) -> bool {
    roll_forward(shared, st).await;
    if shared.exhausted.load(Ordering::Relaxed) {
        return false;
    }
    let cutoff = shared
        .cfg
        .read()
        .expect("lock")
        .cutoff()
        .unwrap_or(u64::MAX);
    let Some(next) = st.charged.checked_add(want) else {
        exhaust(shared, st).await;
        return false;
    };
    if next > cutoff {
        exhaust(shared, st).await;
        return false;
    }
    // Durable BEFORE the worker may spend: the commit precedes the reply.
    if shared
        .store
        .add_charged(&st.period, want as i64)
        .await
        .is_err()
    {
        // Storage failure fails closed: deny, do not spend unrecorded bytes.
        return false;
    }
    st.charged = next;
    maybe_warn(shared, st, cutoff).await;
    true
}

async fn maybe_warn(shared: &Arc<Shared>, st: &mut PeriodState, cutoff: u64) {
    if cutoff == 0 || cutoff == u64::MAX {
        return;
    }
    let pct = (st.charged as u128 * 100 / cutoff as u128) as u64;
    if pct >= 75 {
        shared.store.set_warn(&st.period, 75).await;
        fire_once(shared, st, "warning_75").await;
    }
    if pct >= 90 {
        shared.store.set_warn(&st.period, 90).await;
        fire_once(shared, st, "warning_90").await;
    }
}

/// Persist exhaustion FIRST, then deny and disconnect everyone.
/// Idempotent per period: repeated denied grants do not re-persist,
/// re-disconnect, or re-alert.
async fn exhaust(shared: &Arc<Shared>, st: &mut PeriodState) {
    if shared.exhausted.swap(true, Ordering::Relaxed) {
        return;
    }
    shared.store.set_warn(&st.period, 75).await;
    shared.store.set_warn(&st.period, 90).await;
    shared.store.set_exhausted(&st.period, true).await;
    tracing::warn!(period = %st.period, charged = st.charged, "quota exhausted");
    fire_once(shared, st, "exhausted").await;
    shared.policy.disconnect_all();
}

/// Deliver an alert kind at most once per period. Spawns the POST and
/// returns immediately: delivery never blocks or affects enforcement.
async fn fire_once(shared: &Arc<Shared>, st: &PeriodState, kind: &str) {
    let key = (st.period.clone(), kind.to_string());
    if !shared.fired.write().expect("lock").insert(key) {
        return; // already fired this period (durable flags seed restarts)
    }
    let url = shared.cfg.read().expect("lock").alert_webhook_url.clone();
    let Some(url) = url else { return }; // no sink configured: flag persists, nothing to send
    let payload = serde_json::json!({
        "service": "relay-warden",
        "kind": kind,
        "period": st.period,
        "charged_bytes": st.charged,
    });
    let kind = kind.to_string();
    let shared = shared.clone();
    tokio::spawn(async move {
        let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let result = shared.http.post(&url).json(&payload).send().await;
        let status = match result {
            Ok(r) => {
                let code = r.status();
                if code.is_success() {
                    (true, format!("http {code}"))
                } else {
                    (false, format!("http {code}"))
                }
            }
            Err(e) => (false, format!("{e:#}").chars().take(200).collect()),
        };
        *shared.last_delivery.write().expect("lock") = Some(DeliveryStatus {
            at,
            kind: kind.to_string(),
            ok: status.0,
            detail: status.1,
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_math_conservative_and_saturating() {
        assert_eq!(charged_for(1_000, 0), 1_000);
        assert_eq!(charged_for(1_000, 10), 1_100);
        assert_eq!(charged_for(1, 10), 2); // ceil, never zero-charge
        assert_eq!(charged_for(0, 10), 0);
        assert_eq!(charged_for(usize::MAX, 100), u64::MAX); // saturates, denies downstream
    }

    #[test]
    fn cutoff_subtracts_headroom() {
        let c = QuotaConfig {
            budget_bytes: Some(1_000),
            headroom_bytes: 100,
            overhead_pct: 0,
            chunk_bytes: 1_024,
            alert_webhook_url: None,
        };
        assert_eq!(c.cutoff(), Some(900));
        let c = QuotaConfig {
            budget_bytes: Some(50),
            headroom_bytes: 100,
            ..c
        };
        assert_eq!(c.cutoff(), Some(0));
    }

    #[test]
    fn month_strings_order_chronologically() {
        assert_eq!(month_of(month_start("2026-03").unwrap()), "2026-03");
        assert!("2026-04" > "2026-03");
        // Equal months must NOT trigger a rollover (`now > current` is false).
        assert!("2026-03" <= "2026-03");
    }
}
