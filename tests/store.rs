//! Durable store: SQLite schema, settings, ledgers, audit.
//!
//! Exercises `Store` directly: migrations/guards, versioned settings,
//! endpoint rows, and quota ledger math. No HTTP or relay traffic.

use std::sync::Arc;

use relay_warden::{
    policy::EndpointPolicy,
    store::{Store, SCHEMA_GENERATION},
};

async fn open_named(name: &str) -> (Arc<Store>, TempDir) {
    let dir = std::env::temp_dir().join(format!(
        "warden-store-{name}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Store::open(&dir.join("w.db")).await.unwrap();
    (store, TempDir(dir))
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn store_stamps_generation_and_refuses_newer() {
    let (store, guard) = open_named("gen").await;
    assert_eq!(store.user_version().await.unwrap(), SCHEMA_GENERATION);
    store.set_user_version(99).await.unwrap();
    drop(store);
    let err = Store::open(&guard.0.join("w.db"))
        .await
        .expect_err("newer DB must refuse");
    assert!(err.contains("newer"), "{err}");
}

#[tokio::test]
async fn store_settings_seed_and_versioned_patch() {
    let (store, _guard) = open_named("settings").await;
    // Seeding never overrides.
    store.ensure_setting("k", "1").await.unwrap();
    store.ensure_setting("k", "2").await.unwrap();
    let (v, ver) = store.get_settings().await.unwrap();
    assert_eq!(v["k"], 1);

    // Patch requires the current version.
    let mut patch = serde_json::Map::new();
    patch.insert("k".into(), 3.into());
    assert!(store.patch_settings(ver + 99, &patch).await.is_err());
    let (v, ver2) = store.patch_settings(ver, &patch).await.unwrap();
    assert_eq!(v["k"], 3);
    assert_eq!(ver2, ver + 1);

    // Quota keys validate like the admin path.
    let mut bad = serde_json::Map::new();
    bad.insert("alert_webhook_url".into(), "ftp://x".into());
    assert!(store.patch_settings(ver2, &bad).await.is_err());
    let mut good = serde_json::Map::new();
    good.insert("quota_budget_bytes".into(), 1_000_000.into());
    good.insert("alert_webhook_url".into(), "http://127.0.0.1:9/hook".into());
    let (v, _) = store.patch_settings(ver2, &good).await.unwrap();
    assert_eq!(v["quota_budget_bytes"], 1_000_000);
}

#[tokio::test]
async fn store_endpoint_rows_roundtrip() {
    let (store, _guard) = open_named("endpoints").await;
    let mut e = EndpointPolicy::new("id-1".into(), "one".into());
    e.approved = true;
    store.upsert_endpoint_cas(&e, None).await.unwrap();
    let all = store.list_endpoints().await.unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].approved);

    // Revoke via approval flag is a revision-bumping update.
    let back = store.set_approved("id-1", false).await.unwrap();
    assert!(!back.approved && back.revision == 2);
    assert!(store.set_approved("missing", false).await.is_err());
}

#[tokio::test]
async fn store_quota_ledger_math() {
    let (store, _guard) = open_named("ledger").await;
    let row = store.open_period("2026-03").await.unwrap();
    assert_eq!((row.charged_bytes, row.exhausted), (0, false));

    store.add_charged("2026-03", 1_000).await.unwrap();
    // Proven-unspent returns subtract, floored at zero, never negative.
    store.add_charged("2026-03", -400).await.unwrap();
    store.add_charged("2026-03", -10_000).await.unwrap();
    let row = store.read_period("2026-03").await.unwrap();
    assert_eq!(row.charged_bytes, 0);

    // Missing rows fail closed (caller denies rather than overspends).
    assert!(store.add_charged("2026-99", 10).await.is_err());

    store.set_warn("2026-03", 75).await;
    store.set_exhausted("2026-03", true).await;
    let row = store.read_period("2026-03").await.unwrap();
    assert!(row.warn75 && !row.warn90 && row.exhausted);

    // History is never deleted by opening new periods.
    store.open_period("2026-04").await.unwrap();
    assert!(store.read_period("2026-03").await.unwrap().exhausted);
}

#[tokio::test]
async fn store_rejected_patch_commits_nothing() {
    let (store, _guard) = open_named("atomic").await;
    let (before, version) = store.get_settings().await.unwrap();
    // Valid speed change + invalid budget: the whole patch must fail.
    let mut patch = serde_json::Map::new();
    patch.insert("default_rx_bps".into(), 2_000.into());
    patch.insert("quota_budget_bytes".into(), (-1).into());
    assert!(store.patch_settings(version, &patch).await.is_err());
    let (after, new_version) = store.get_settings().await.unwrap();
    assert_eq!(new_version, version, "rejected patch bumped the version");
    assert_eq!(after, before, "rejected patch committed some settings");
}

#[tokio::test]
async fn store_rollback_reconciliation_preserves_spent_quota() {
    // Mirrors the documented rollback reconciliation in OPERATIONS.md: carry
    // each period's charged bytes and exhaustion forward by maximum, so a
    // restored backup can never resurrect spent allowance.
    let (live, live_dir) = open_named("live").await;
    let (backup, backup_dir) = open_named("backup").await;
    live.open_period("2026-03").await.unwrap();
    live.add_charged("2026-03", 90_000).await.unwrap();
    live.set_exhausted("2026-03", true).await;
    backup.open_period("2026-03").await.unwrap();
    backup.add_charged("2026-03", 10_000).await.unwrap();
    drop(live);
    drop(backup);
    // The documented procedure, executed as SQL (tested here, not just docs).
    let live_path = live_dir.0.join("w.db");
    let backup_path = backup_dir.0.join("w.db");
    let merged = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&live_path).unwrap();
        conn.execute("ATTACH ? AS b", [backup_path.to_str().unwrap()]).unwrap();
        conn.execute(
            "UPDATE quota_periods SET charged_bytes = max(charged_bytes, (SELECT charged_bytes FROM b.quota_periods WHERE period = quota_periods.period)), exhausted = exhausted OR (SELECT exhausted FROM b.quota_periods WHERE period = quota_periods.period)",
            [],
        )
        .unwrap();
        conn.query_row(
            "SELECT charged_bytes, exhausted FROM quota_periods WHERE period='2026-03'",
            [],
            |r| Ok((r.get::<_, i64>(0).unwrap(), r.get::<_, i32>(1).unwrap())),
        )
        .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(merged, (90_000, 1));
}

#[tokio::test]
async fn store_audit_appends() {
    let (store, _guard) = open_named("audit").await;
    store.append_audit("admin", "login", "", "").await;
    store
        .append_audit("admin", "endpoint_revoke", "abc", "")
        .await;
    let events = store.recent_audit(10).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["action"], "endpoint_revoke");
    assert!(store.recent_audit(1).await.unwrap().len() == 1);
}
