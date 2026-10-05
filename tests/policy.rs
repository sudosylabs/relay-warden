//! Endpoint policy: records, admission decisions, live tracking.
//!
//! Exercises `PolicyManager` directly (no HTTP, no relay traffic): the domain
//! logic the admin API and the relay embedding both rely on.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use iroh_base::SecretKey;
use iroh_relay::{
    http::ProtocolVersion,
    server::{Access, AccessControl, ClientRequest},
};
use relay_warden::{
    policy::{EndpointUpsert, PolicyManager, SpeedPolicy},
    store::Store,
};

fn upsert(
    label: Option<&str>,
    approved: Option<bool>,
    speed_policy: Option<&str>,
    revision: Option<i64>,
) -> EndpointUpsert {
    use relay_warden::policy::TriState::Unchanged;
    EndpointUpsert {
        label: label.map(str::to_string),
        approved,
        speed_policy: speed_policy.map(str::to_string),
        custom_rx_bps: Unchanged,
        custom_tx_bps: Unchanged,
        burst_bytes: Unchanged,
        revision,
    }
}

fn parts() -> http::request::Parts {
    http::Request::builder()
        .uri("http://localhost/relay")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

async fn manager() -> (Arc<PolicyManager>, TempDir) {
    let dir = std::env::temp_dir().join(format!(
        "warden-policy-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Store::open(&dir.join("w.db")).await.unwrap();
    let mgr = PolicyManager::open(store).await.unwrap();
    (mgr, TempDir(dir))
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn policy_validates_records_and_revisions() {
    let (m, _g) = manager().await;
    let id = SecretKey::generate().public().to_string();

    // Unknown speed policy rejected.
    assert!(m
        .upsert(&id, &upsert(Some("x"), Some(true), Some("ludicrous"), None))
        .await
        .is_err());
    // Custom without any direction rejected.
    assert!(m
        .upsert(&id, &upsert(Some("x"), Some(true), Some("custom"), None))
        .await
        .is_err());
    // Over-long label rejected.
    assert!(m
        .upsert(&id, &upsert(Some(&"x".repeat(200)), None, None, None))
        .await
        .is_err());

    // Create (no revision needed), then update requires the current revision.
    let rec = m
        .upsert(&id, &upsert(Some("dev <b>"), Some(true), None, None))
        .await
        .unwrap();
    assert_eq!(
        (rec.revision, rec.label.as_str(), rec.approved),
        (1, "dev <b>", true)
    );
    assert!(m
        .upsert(&id, &upsert(Some("second"), None, None, None))
        .await
        .is_err());
    assert!(m
        .upsert(&id, &upsert(Some("stale"), None, None, Some(999)))
        .await
        .is_err());
    let rec = m
        .upsert(&id, &upsert(Some("second"), None, None, Some(1)))
        .await
        .unwrap();
    assert_eq!((rec.revision, rec.label.as_str()), (2, "second"));

    // Unlimited must not carry directional overrides.
    let rec = m
        .upsert(&id, &upsert(None, None, Some("unlimited"), Some(2)))
        .await
        .unwrap();
    assert_eq!(rec.speed_policy, SpeedPolicy::Unlimited);
    let mut bad = upsert(None, None, Some("unlimited"), Some(3));
    bad.custom_rx_bps = relay_warden::policy::TriState::Set(1000);
    assert!(m.upsert(&id, &bad).await.is_err());
}

#[tokio::test]
async fn policy_persists_across_reopen() {
    let dir = std::env::temp_dir().join(format!(
        "warden-polpersist-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("w.db");
    let id = SecretKey::generate().public().to_string();
    {
        let store = Store::open(&db).await.unwrap();
        let m = PolicyManager::open(store).await.unwrap();
        m.upsert(
            &id,
            &upsert(Some("persist"), Some(true), Some("unlimited"), None),
        )
        .await
        .unwrap();
    }
    // Fresh manager over the same file (simulated restart).
    let store = Store::open(&db).await.unwrap();
    let m = PolicyManager::open(store).await.unwrap();
    let rec = m.get(&id).expect("persisted");
    assert_eq!(
        (rec.label.as_str(), rec.approved, rec.revision),
        ("persist", true, 1)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn policy_admission_cache_and_live_counts() {
    let (m, _g) = manager().await;
    let id = SecretKey::generate().public();

    // Unknown -> deny, no live count.
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
    let idle_id = req.connection_id();
    assert!(matches!(m.on_connect(&req).await, Access::Deny { .. }));
    assert_eq!(m.live_count(&id.to_string()), 0);

    // Approve -> allow tracks one live connection.
    m.upsert(
        &id.to_string(),
        &upsert(Some("live"), Some(true), None, None),
    )
    .await
    .unwrap();
    let req2 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    let conn = req2.connection_id();
    assert!(matches!(m.on_connect(&req2).await, Access::Allow));
    assert_eq!(m.live_count(&id.to_string()), 1);

    // Revoke publishes synchronously: later admissions deny immediately.
    m.revoke(&id.to_string()).await.unwrap();
    let req3 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(m.on_connect(&req3).await, Access::Deny { .. }));

    // Disconnects balance admissions; unknown disconnects are no-ops.
    m.on_disconnect(id, conn);
    m.on_disconnect(id, idle_id);
    assert_eq!(m.live_count(&id.to_string()), 0);
}

#[tokio::test]
async fn policy_per_endpoint_cap_denies_with_balance() {
    let (m, _g) = manager().await;
    m.set_max_per_endpoint(Some(1));
    let id = SecretKey::generate().public();
    m.upsert(&id.to_string(), &upsert(Some("c"), Some(true), None, None))
        .await
        .unwrap();

    let r1 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    let c1 = r1.connection_id();
    assert!(matches!(m.on_connect(&r1).await, Access::Allow));
    let r2 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(m.on_connect(&r2).await, Access::Deny { .. }));
    m.on_disconnect(id, c1);
    let r3 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(m.on_connect(&r3).await, Access::Allow));
}

#[tokio::test]
async fn policy_revoke_bumps_revision_and_unapproves() {
    let (m, _g) = manager().await;
    let id = SecretKey::generate().public().to_string();
    m.upsert(&id, &upsert(Some("r"), Some(true), None, None))
        .await
        .unwrap();
    let (rec, had_live) = m.revoke(&id).await.unwrap();
    assert!(!rec.approved && !had_live && rec.revision == 2);
    assert!(m.revoke("not-a-key").await.is_err());
}

#[tokio::test]
async fn policy_canonicalizes_alternate_id_spellings() {
    let (m, _g) = manager().await;
    let id = SecretKey::generate().public();
    // Base32 spelling of the same key (FromStr accepts hex or base32).
    let spelled = data_encoding::BASE32_NOPAD.encode(id.as_bytes());
    assert_ne!(spelled, id.to_string());
    m.upsert(&spelled, &upsert(Some("alt"), Some(true), None, None))
        .await
        .unwrap();
    // Stored and served under the canonical hex spelling only.
    let rec = m.get(&id.to_string()).expect("canonical lookup must hit");
    assert_eq!(rec.endpoint_id, id.to_string());
    assert_eq!(m.list().len(), 1);
    // Admission resolves the same record.
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(m.on_connect(&req).await, Access::Allow));
}

#[tokio::test]
async fn policy_concurrent_edits_single_winner_per_revision() {
    let (m, _g) = manager().await;
    let id = SecretKey::generate().public().to_string();
    let original = m
        .upsert(&id, &upsert(Some("base"), Some(true), None, None))
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();
    for i in 0..16 {
        let m = m.clone();
        let id = id.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            m.upsert(
                &id,
                &upsert(
                    Some(&format!("edit-{i}")),
                    None,
                    None,
                    Some(original.revision),
                ),
            )
            .await
            .is_ok()
        }));
    }
    let mut successes = 0;
    for t in tasks {
        if t.await.unwrap() {
            successes += 1;
        }
    }
    assert_eq!(
        successes, 1,
        "{successes} edits succeeded against the same revision"
    );
    // The winning row is coherent: exactly one label at revision 2.
    let rec = m.get(&id).unwrap();
    assert_eq!(rec.revision, 2);
}

#[test]
fn policy_custom_limits_clear_to_unlimited() {
    use relay_warden::policy::{apply_upsert, EndpointUpsert};
    let id = SecretKey::generate().public().to_string();
    let custom: EndpointUpsert =
        serde_json::from_value(serde_json::json!({"speed_policy":"custom","custom_rx_bps":1000}))
            .unwrap();
    let record = apply_upsert(None, &id, &custom).unwrap();
    // Explicit nulls clear; omitted fields would leave the cap in place.
    let unlimited: EndpointUpsert = serde_json::from_value(
        serde_json::json!({"revision":record.revision,"speed_policy":"unlimited","custom_rx_bps":null,"custom_tx_bps":null}),
    )
    .unwrap();
    assert!(
        apply_upsert(Some(&record), &id, &unlimited).is_ok(),
        "cannot clear a custom cap to make device unlimited"
    );
    // ...while omitting the rates really does leave them (and then fails).
    let stuck: EndpointUpsert = serde_json::from_value(
        serde_json::json!({"revision":record.revision,"speed_policy":"unlimited"}),
    )
    .unwrap();
    assert!(apply_upsert(Some(&record), &id, &stuck).is_err());
}

#[tokio::test]
async fn policy_quota_flag_denies_admission() {
    let (m, _g) = manager().await;
    let id = SecretKey::generate().public();
    m.upsert(&id.to_string(), &upsert(Some("q"), Some(true), None, None))
        .await
        .unwrap();

    let flag = Arc::new(AtomicBool::new(false));
    m.set_quota_exhausted(Some(flag.clone()));
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
    let conn = req.connection_id();
    assert!(matches!(m.on_connect(&req).await, Access::Allow));
    assert_eq!(m.live_count(&id.to_string()), 1);

    flag.store(true, Ordering::Relaxed);
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
    match m.on_connect(&req).await {
        Access::Deny { reason } => assert!(reason.unwrap_or_default().contains("exhausted")),
        Access::Allow => panic!("exhausted budget must deny"),
    }
    // ...and revalidation disconnects in-flight admissions (no panic without clients).
    m.revalidate(&id);
    m.on_disconnect(id, conn);
    assert_eq!(m.live_count(&id.to_string()), 0);
}
