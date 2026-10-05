//! Shared monthly outbound budget enforcement.
//!
//! Small synthetic budgets (never terabytes) and a manual clock: exact
//! concurrent-grant boundaries, exhaustion that closes everything including
//! owners, charging of both traffic classes, crash-preserved ledgers,
//! forward-only month rollover, and budget-cut behavior. Unit math (charge
//! formula, cutoff, month ordering) lives in `src/quota.rs`.

mod common;

use std::{sync::Arc, time::Duration};

use common::{
    admin_client, approve, endpoint_json, expect_close, get_settings, patch_settings,
    relay_connect, start, transfer, usage, Harness, HarnessOptions, QuotaOpts,
};
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{ClientBuilder, ConnectError},
    protos::{
        handshake,
        relay::{Datagrams, RelayToClientMsg},
    },
    tls::{default_provider, CaTlsConfig},
};
use n0_future::{SinkExt, StreamExt};
use relay_warden::{
    policy::PolicyManager,
    quota::{month_start, Clock, ManualClock},
    store::Store,
};

fn quota_opts(budget: u64) -> QuotaOpts {
    QuotaOpts {
        budget,
        headroom: 0,
        overhead: 0,
        chunk: 8_192,
    }
}

async fn start_quota(budget: u64) -> Harness {
    start(HarnessOptions {
        ordinary_limits: Some((10_000_000, 10_000_000)),
        quota: Some(quota_opts(budget)),
        ..Default::default()
    })
    .await
}

async fn pump(tx: &mut iroh_relay::client::Client, dst: EndpointId, n: usize) {
    for i in 0..n {
        let mut v = vec![0u8; 2048];
        v[..4].copy_from_slice(&(i as u32).to_be_bytes());
        if tx
            .send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst,
                datagrams: Datagrams::from(v),
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[tokio::test]
async fn quota_concurrent_grants_cannot_exceed_cutoff() {
    let h = start_quota(200_000).await;
    let quota = h.quota.clone().expect("quota enabled");
    // 10 concurrent acquirers x 25k: exactly 8 fit, sum == cutoff exactly.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let q = quota.clone();
        tasks.push(tokio::spawn(async move { q.acquire(25_000).await }));
    }
    let mut granted = 0u64;
    let mut denied = 0;
    for t in tasks {
        if t.await.unwrap() {
            granted += 25_000;
        } else {
            denied += 1;
        }
    }
    assert_eq!(granted, 200_000, "grants must total exactly the cutoff");
    assert_eq!(denied, 2);
    let u = usage(&h).await;
    assert_eq!(u["charged_bytes"], 200_000);
    // The denied grants persist exhaustion (denial and persistence are one step).
    assert!(quota.exhausted());
    assert_eq!(u["exhausted"], true);
}

#[tokio::test]
async fn quota_exhaustion_closes_all_including_owner() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_quota(120_000).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    approve(&h, &c_id, serde_json::json!({"speed_policy": "unlimited"})).await;

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    let mut c = relay_connect(h.relay_addr, c_sk).await;

    // Pump from both ordinary (A) and owner (C) into B until the relay stops.
    let recv_all = async {
        let mut n = 0usize;
        let mut bytes = 0usize;
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(30), b.next()).await {
            match msg {
                Ok(RelayToClientMsg::Datagrams { datagrams, .. }) => {
                    n += 1;
                    bytes += datagrams.contents.len();
                }
                _ => break, // closed / error / timeout: relay stopped
            }
        }
        (n, bytes)
    };
    let ((), (), (n, bytes)) =
        tokio::join!(pump(&mut a, b_id, 500), pump(&mut c, b_id, 500), recv_all);
    assert!(
        n > 10,
        "expected substantial traffic before exhaustion, got {n}"
    );

    // Charged never exceeds the cutoff; received is bounded by cutoff plus
    // in-flight debt (one frame per delivering connection at the edge).
    let u = usage(&h).await;
    assert_eq!(u["exhausted"], true);
    assert!(u["charged_bytes"].as_u64().unwrap() <= 120_000);
    assert!(u["charged_bytes"].as_u64().unwrap() > 120_000 - 8_192);
    assert!(
        bytes as u64 <= 120_000 + 16_384,
        "received {bytes} exceeds cutoff + in-flight bound"
    );
    assert_eq!(u["warnings"]["w75"], true);
    assert_eq!(u["warnings"]["w90"], true);

    // All relay connections closed, including the unlimited owner's.
    for (name, mut cl) in [("a", a), ("c", c)] {
        expect_close(&mut cl, &format!("{name} connection")).await;
    }

    // New admissions denied with the quota reason; admin still usable.
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("tls");
    let err = ClientBuilder::new(url, SecretKey::generate(), DnsResolver::new())
        .tls_client_config(tls)
        .connect()
        .await
        .expect_err("exhausted relay must deny");
    assert!(
        matches!(
            err,
            ConnectError::Handshake {
                source: handshake::Error::ServerDeniedAuth { .. },
                ..
            }
        ),
        "got {err:?}"
    );
    let st: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/status", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["db_ok"], true);
}

#[tokio::test]
async fn quota_owner_and_ordinary_both_charged() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_quota(200_000).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    approve(&h, &c_id, serde_json::json!({"speed_policy": "unlimited"})).await;

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    let mut c = relay_connect(h.relay_addr, c_sk).await;

    transfer(&mut a, &mut b, b_id, 20, 2048).await; // ordinary -> ordinary
    transfer(&mut c, &mut b, b_id, 20, 2048).await; // owner -> ordinary
    let u = usage(&h).await;
    let charged = u["charged_bytes"].as_u64().unwrap();
    // Both directions charged (overhead 0): >= 81_920 payload, slack bounded
    // by two connection leases' unused remainders.
    assert!(
        charged >= 81_920,
        "both classes must be charged, got {charged}"
    );
    assert!(
        charged <= 81_920 + 2 * 8_192 + 8_192,
        "over-charge? {charged}"
    );
    assert_eq!(u["exhausted"], false);
    let _ = (a, b, c);
}

#[tokio::test]
async fn quota_crash_preserves_ledger() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_quota(200_000).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    transfer(&mut a, &mut b, b_id, 25, 2048).await;

    let u1 = usage(&h).await;
    let charged1 = u1["charged_bytes"].as_u64().unwrap();
    assert!(charged1 >= 25 * 2048, "grants must cover sent bytes");
    drop((a, b));
    let db_path = h.db_path.clone();
    let month = h.clock.clone().expect("clock").month();
    drop(h); // simulated crash: no clean shutdown, returns may be lost

    // Reopen the same database: spent quota is not restored.
    let store = Store::open(&db_path).await.unwrap();
    let row = store.read_period(&month).await.unwrap();
    assert_eq!(row.charged_bytes, charged1, "ledger must survive restart");
    assert!(!row.exhausted);
    // A fresh manager continues from the preserved ledger: the remaining
    // headroom is exactly budget - charged, so one byte more denies.
    let policy = PolicyManager::open(store).await.unwrap();
    let clock = Arc::new(ManualClock::new(
        month_start("2026-03").unwrap() + Duration::from_secs(14 * 86_400),
    ));
    let q = relay_warden::quota::QuotaManager::open(
        policy.store().clone(),
        policy,
        clock as Arc<dyn Clock>,
    )
    .await
    .unwrap();
    assert!(q.acquire(200_000 - charged1).await);
    assert!(!q.acquire(1).await, "ledger must continue, not reset");
}

#[tokio::test]
async fn quota_month_rollover_and_backward_clock() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_quota(200_000).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    transfer(&mut a, &mut b, b_id, 10, 2048).await;
    let mar = usage(&h).await;
    assert_eq!(mar["period"], "2026-03");
    let mar_charged = mar["charged_bytes"].as_u64().unwrap();
    assert!(mar_charged >= 10 * 2048);

    // Forward jump opens a fresh ledger (mid-connection leases re-grant).
    h.clock
        .clone()
        .expect("clock")
        .set(month_start("2026-04").unwrap() + Duration::from_secs(9 * 86_400));
    h.quota.clone().expect("quota").refresh().await;
    transfer(&mut a, &mut b, b_id, 5, 2048).await;
    let apr = usage(&h).await;
    assert_eq!(apr["period"], "2026-04");
    let apr_charged = apr["charged_bytes"].as_u64().unwrap();
    assert!(apr_charged >= 5 * 2048 && apr_charged < mar_charged + 5 * 2048 + 8_192);

    // Backward clock never reopens the older period.
    h.clock
        .clone()
        .expect("clock")
        .set(month_start("2026-03").unwrap() + Duration::from_secs(20 * 86_400));
    h.quota.clone().expect("quota").refresh().await;
    let back = usage(&h).await;
    assert_eq!(back["period"], "2026-04");
    assert_eq!(back["charged_bytes"], apr_charged);
}

#[tokio::test]
async fn quota_alerts_fire_once_per_period() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_quota(100_000).await;
    // Capture server for webhook POSTs.
    let seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_clone = seen.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(v): axum::Json<serde_json::Value>| {
            let seen_clone = seen_clone.clone();
            async move {
                seen_clone.lock().unwrap().push(v);
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    // Point the sink at the capture server via the versioned settings path.
    let s = get_settings(&h).await;
    let r = patch_settings(
        &h,
        s["version"].as_i64().unwrap(),
        serde_json::json!({"alert_webhook_url": format!("http://{hook_addr}/hook")}),
    )
    .await;
    assert_eq!(r.status(), 200);

    let kinds = || {
        seen.lock()
            .unwrap()
            .iter()
            .map(|v| v["kind"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    // Past 75% of 100k with 2KiB frames.
    for i in 0..40u32 {
        let mut v = vec![0u8; 2048];
        v[..4].copy_from_slice(&i.to_be_bytes());
        if a.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_id,
            datagrams: Datagrams::from(v),
        })
        .await
        .is_err()
        {
            break;
        }
        let _ = tokio::time::timeout(Duration::from_millis(200), b.next()).await;
    }
    for _ in 0..100 {
        if kinds().contains(&"warning_75".to_string()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        kinds().contains(&"warning_75".to_string()),
        "no warning_75: {:?}",
        kinds()
    );
    // Keep pushing to exhaustion: warning_90 + exhausted fire, 75 does not repeat.
    for _ in 40..120u32 {
        pump(&mut a, b_id, 1).await;
        let _ = tokio::time::timeout(Duration::from_millis(50), b.next()).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let kinds = kinds();
    assert_eq!(
        kinds.iter().filter(|k| *k == "warning_75").count(),
        1,
        "re-fired 75!"
    );
    assert!(
        kinds.contains(&"warning_90".to_string()),
        "no warning_90: {kinds:?}"
    );
    assert_eq!(kinds.iter().filter(|k| *k == "exhausted").count(), 1);

    // Payload carries period + charged units, never traffic content.
    let snap: Vec<serde_json::Value> = seen.lock().unwrap().clone();
    assert_eq!(snap[0]["period"], "2026-03");
    assert!(snap[0]["charged_bytes"].as_u64().unwrap() > 0);
    assert!(!serde_json::to_string(&snap)
        .unwrap()
        .contains(&a_id.to_string()));
    let _ = (a, b);
}

#[tokio::test]
async fn quota_budget_cut_exhausts_but_edits_do_not_reset() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_quota(200_000).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    transfer(&mut a, &mut b, b_id, 30, 2048).await;

    let before = usage(&h).await;
    let charged = before["charged_bytes"].as_u64().unwrap();
    assert!(charged >= 30 * 2048);

    // Cut the budget below current usage: immediate exhaustion + disconnect.
    let s = get_settings(&h).await;
    let r = patch_settings(
        &h,
        s["version"].as_i64().unwrap(),
        serde_json::json!({"quota_budget_bytes": 10_000}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let cut = usage(&h).await;
    assert_eq!(cut["exhausted"], true);
    // Proven-unspent lease remainders are handed back on disconnect, so the
    // counter may settle slightly below the pre-cut reading — but never reset
    // and never below the bytes actually delivered.
    let cut_charged = cut["charged_bytes"].as_u64().unwrap();
    assert!(cut_charged <= charged, "usage must not grow on cut");
    assert!(cut_charged >= 30 * 2048, "delivered bytes stay charged");
    expect_close(&mut b, "budget cut").await;

    // Ordinary endpoint edit changes neither usage nor exhaustion.
    let entry = endpoint_json(&h, &a_id).await;
    let rev = entry["revision"].as_i64().unwrap();
    let r = admin_client(&h.token)
        .put(format!("http://{}/admin/endpoints/{a_id}", h.admin_addr))
        .json(&serde_json::json!({"label": "renamed", "revision": rev}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let after_edit = usage(&h).await;
    assert_eq!(after_edit["exhausted"], true);
    assert_eq!(after_edit["charged_bytes"], cut_charged);

    // Honest re-budget above usage reopens (distinct audited action).
    let s = get_settings(&h).await;
    let r = patch_settings(
        &h,
        s["version"].as_i64().unwrap(),
        serde_json::json!({"quota_budget_bytes": 500_000}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(usage(&h).await["exhausted"], false);
    let audit: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/audit?limit=20", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let text = serde_json::to_string(&audit).unwrap();
    assert!(
        text.contains("quota_reevaluated"),
        "budget actions must be audited"
    );
    let _ = a;
}
