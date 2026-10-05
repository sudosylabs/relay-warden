//! Gate D: durable monthly enforcement.
//!
//! Small synthetic budgets (10^5 bytes), never terabytes. Manual clock for
//! periods; real relay traffic for the enforcement path.

use std::{net::SocketAddr, sync::Arc, time::Duration};

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
    admin::{load_admin_token, AdminState},
    limiter::LimiterMap,
    policy::PolicyManager,
    quota::{month_start, Clock, ManualClock, QuotaManager},
    store::Store,
};

fn tls_config() -> rustls::ClientConfig {
    CaTlsConfig::default()
        .client_config(default_provider())
        .expect("tls")
}

struct Harness {
    relay_addr: SocketAddr,
    admin_addr: SocketAddr,
    token: String,
    clock: Arc<ManualClock>,
    quota: Arc<QuotaManager>,
    db_path: std::path::PathBuf,
    _relay_handle: n0_future::task::AbortOnDropHandle<()>,
    _admin_handle: n0_future::task::AbortOnDropHandle<()>,
}

/// Budget 200k, no headroom/overhead (exact boundaries), 8k chunks.
/// Limiter 10MB/s so only quota shapes.
async fn start_harness() -> Harness {
    start_harness_with(200_000, 0, 0, 8_192).await
}

async fn start_harness_with(budget: u64, headroom: u64, overhead: u64, chunk: u64) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "warden-d-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("warden.db");
    let token_path = dir.join("admin.token");
    let token = format!(
        "test-token-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    std::fs::write(&token_path, &token).unwrap();

    let token_bytes = load_admin_token(token_path.to_str().unwrap()).unwrap();
    let store = Store::open(&db_path).await.unwrap();
    store
        .ensure_defaults(Some(10_000_000), Some(10_000_000))
        .await
        .unwrap();
    store
        .ensure_setting("quota_budget_bytes", &budget.to_string())
        .await
        .unwrap();
    store
        .ensure_setting("quota_headroom_bytes", &headroom.to_string())
        .await
        .unwrap();
    store
        .ensure_setting("quota_overhead_pct", &overhead.to_string())
        .await
        .unwrap();
    store
        .ensure_setting("quota_chunk_bytes", &chunk.to_string())
        .await
        .unwrap();

    let clock = Arc::new(ManualClock::new(
        month_start("2026-03").unwrap() + Duration::from_secs(14 * 86_400),
    ));
    let policy = PolicyManager::open(store.clone()).await.unwrap();
    let limiter = LimiterMap::new();
    let quota = QuotaManager::open(
        store,
        policy.clone(),
        clock.clone() as Arc<dyn relay_warden::quota::Clock>,
    )
    .await
    .unwrap();

    let relay_state = relay_warden::relay::RelayState::new(
        policy.clone() as Arc<dyn iroh_relay::server::DynAccessControl>,
        1024,
        64,
        Duration::from_secs(10),
    )
    .with_policy(policy.clone())
    .with_limiter(limiter.clone())
    .with_quota(quota.client());
    quota.set_clients(relay_state.clients.clone());
    let (relay_addr, _relay_handle) =
        relay_warden::relay::serve("127.0.0.1:0".parse().unwrap(), relay_state)
            .await
            .unwrap();

    let admin_state = AdminState::new(policy, limiter, Some(quota.clone()), token_bytes);
    let app = relay_warden::admin::router(admin_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let _admin_handle = n0_future::task::AbortOnDropHandle::new(task);

    Harness {
        relay_addr,
        admin_addr,
        token,
        clock,
        quota,
        db_path,
        _relay_handle,
        _admin_handle,
    }
}

fn admin_client(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

async fn approve(h: &Harness, id: &EndpointId, body: serde_json::Value) {
    let mut map = serde_json::Map::new();
    map.insert("label".into(), "t".into());
    map.insert("approved".into(), true.into());
    if let serde_json::Value::Object(extra) = body {
        for (k, v) in extra {
            map.insert(k, v);
        }
    }
    let r = admin_client(&h.token)
        .put(format!("http://{}/admin/endpoints/{id}", h.admin_addr))
        .json(&serde_json::Value::Object(map))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "approve {id}: {:?}",
        r.text().await.unwrap()
    );
}

async fn relay_connect(relay_addr: SocketAddr, sk: SecretKey) -> iroh_relay::client::Client {
    let url: RelayUrl = format!("http://{relay_addr}").parse().unwrap();
    ClientBuilder::new(url, sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect("relay connect")
}

async fn usage(h: &Harness) -> serde_json::Value {
    admin_client(&h.token)
        .get(format!("http://{}/admin/usage", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn quota_concurrent_grants_cannot_exceed_cutoff() {
    let h = start_harness().await; // budget 200k
                                   // 10 concurrent acquirers x 25k: exactly 8 fit, sum == cutoff exactly.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let q = h.quota.clone();
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
    assert!(h.quota.exhausted());
    assert_eq!(u["exhausted"], true);
}

#[tokio::test]
async fn quota_exhaustion_closes_all_including_owner() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness_with(120_000, 0, 0, 8_192).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let _b_id = b_sk.public();
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &c_id, serde_json::json!({"speed_policy": "unlimited"})).await;
    // B approved too (receiver).
    let b_id = {
        approve(&h, &_b_id, serde_json::json!({})).await;
        _b_id
    };

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    let mut c = relay_connect(h.relay_addr, c_sk).await;

    // Pump from both ordinary (A) and owner (C) into B until the relay stops.
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
    let recv_all = async {
        let mut n = 0usize;
        let mut bytes = 0usize;
        // Ends on close, error, or timeout: the relay stopped.
        while let Ok(Some(Ok(RelayToClientMsg::Datagrams { datagrams, .. }))) =
            tokio::time::timeout(Duration::from_secs(30), b.next()).await
        {
            n += 1;
            bytes += datagrams.contents.len();
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
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match cl.next().await {
                    None | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "{name} (owner={}) did not close",
            name == "c"
        );
    }

    // New admissions denied with the quota reason; admin still usable.
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let err = ClientBuilder::new(url, SecretKey::generate(), DnsResolver::new())
        .tls_client_config(tls_config())
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
    let h = start_harness().await; // 200k, overhead 0
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

    // 20 x 2KiB each direction pair (40_960 payload each way).
    async fn leg(
        tx: &mut iroh_relay::client::Client,
        rx: &mut iroh_relay::client::Client,
        dst: EndpointId,
    ) {
        for i in 0..20 {
            let mut v = vec![0u8; 2048];
            v[..4].copy_from_slice(&(i as u32).to_be_bytes());
            tx.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst,
                datagrams: Datagrams::from(v),
            })
            .await
            .unwrap();
        }
        for _ in 0..20 {
            loop {
                match tokio::time::timeout(Duration::from_secs(20), rx.next())
                    .await
                    .expect("timeout")
                {
                    Some(Ok(RelayToClientMsg::Datagrams { .. })) => break,
                    Some(Ok(_)) => continue,
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }
    leg(&mut a, &mut b, b_id).await; // ordinary -> ordinary
    leg(&mut c, &mut b, b_id).await; // owner -> ordinary
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
    let h = start_harness().await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    for i in 0..25 {
        let mut v = vec![0u8; 2048];
        v[..4].copy_from_slice(&(i as u32).to_be_bytes());
        a.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_id,
            datagrams: Datagrams::from(v),
        })
        .await
        .unwrap();
    }
    for _ in 0..25 {
        loop {
            match tokio::time::timeout(Duration::from_secs(20), b.next())
                .await
                .expect("t")
            {
                Some(Ok(RelayToClientMsg::Datagrams { .. })) => break,
                Some(Ok(_)) => continue,
                other => panic!("{other:?}"),
            }
        }
    }
    let u1 = usage(&h).await;
    let charged1 = u1["charged_bytes"].as_u64().unwrap();
    assert!(charged1 >= 25 * 2048, "grants must cover sent bytes");
    drop((a, b));
    let db_path = h.db_path.clone();
    let month = h.clock.month();
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
    let q = QuotaManager::open(
        policy.store().clone(),
        policy,
        clock as Arc<dyn relay_warden::quota::Clock>,
    )
    .await
    .unwrap();
    assert!(q.acquire(200_000 - charged1).await);
    assert!(!q.acquire(1).await, "ledger must continue, not reset");
}

#[tokio::test]
async fn quota_month_rollover_and_backward_clock() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    async fn send_n(
        tx: &mut iroh_relay::client::Client,
        rx: &mut iroh_relay::client::Client,
        dst: EndpointId,
        n: usize,
    ) {
        for i in 0..n {
            let mut v = vec![0u8; 2048];
            v[..4].copy_from_slice(&(i as u32).to_be_bytes());
            tx.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst,
                datagrams: Datagrams::from(v),
            })
            .await
            .unwrap();
        }
        for _ in 0..n {
            loop {
                match tokio::time::timeout(Duration::from_secs(20), rx.next())
                    .await
                    .expect("t")
                {
                    Some(Ok(RelayToClientMsg::Datagrams { .. })) => break,
                    Some(Ok(_)) => continue,
                    other => panic!("{other:?}"),
                }
            }
        }
    }
    send_n(&mut a, &mut b, b_id, 10).await;
    let mar = usage(&h).await;
    assert_eq!(mar["period"], "2026-03");
    let mar_charged = mar["charged_bytes"].as_u64().unwrap();
    assert!(mar_charged >= 10 * 2048);

    // Forward jump opens a fresh ledger (mid-connection leases re-grant).
    h.clock
        .set(month_start("2026-04").unwrap() + Duration::from_secs(9 * 86_400));
    h.quota.refresh().await;
    send_n(&mut a, &mut b, b_id, 5).await;
    let apr = usage(&h).await;
    assert_eq!(apr["period"], "2026-04");
    let apr_charged = apr["charged_bytes"].as_u64().unwrap();
    assert!(apr_charged >= 5 * 2048 && apr_charged < mar_charged + 5 * 2048 + 8_192);

    // Backward clock never reopens the older period.
    h.clock
        .set(month_start("2026-03").unwrap() + Duration::from_secs(20 * 86_400));
    h.quota.refresh().await;
    let back = usage(&h).await;
    assert_eq!(back["period"], "2026-04");
    assert_eq!(back["charged_bytes"], apr_charged);
}

#[tokio::test]
async fn quota_budget_cut_exhausts_but_edits_do_not_reset() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await; // 200k
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    for i in 0..30 {
        let mut v = vec![0u8; 2048];
        v[..4].copy_from_slice(&(i as u32).to_be_bytes());
        a.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_id,
            datagrams: Datagrams::from(v),
        })
        .await
        .unwrap();
    }
    for _ in 0..30 {
        loop {
            match tokio::time::timeout(Duration::from_secs(20), b.next())
                .await
                .expect("t")
            {
                Some(Ok(RelayToClientMsg::Datagrams { .. })) => break,
                Some(Ok(_)) => continue,
                other => panic!("{other:?}"),
            }
        }
    }
    let before = usage(&h).await;
    let charged = before["charged_bytes"].as_u64().unwrap();
    assert!(charged >= 30 * 2048);

    // Cut the budget below current usage: immediate exhaustion + disconnect.
    let s: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/settings", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r = admin_client(&h.token)
        .patch(format!("http://{}/admin/settings", h.admin_addr))
        .json(&serde_json::json!({"version": s["version"], "settings": {"quota_budget_bytes": 10_000}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let cut = usage(&h).await;
    assert_eq!(cut["exhausted"], true);
    // Proven-unspent lease remainders are handed back on disconnect, so the
    // counter may settle slightly below the pre-cut reading — but never reset
    // and never below the bytes actually delivered.
    let cut_charged = cut["charged_bytes"].as_u64().unwrap();
    assert!(cut_charged <= charged, "usage must not grow on cut");
    assert!(cut_charged >= 30 * 2048, "delivered bytes stay charged");
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match b.next().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "budget cut must close connections");

    // Ordinary endpoint edit changes neither usage nor exhaustion.
    let list: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/endpoints", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rev = list["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["endpoint_id"] == a_id.to_string())
        .unwrap()["revision"]
        .as_i64()
        .unwrap();
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
    let s: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/settings", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r = admin_client(&h.token)
        .patch(format!("http://{}/admin/settings", h.admin_addr))
        .json(&serde_json::json!({"version": s["version"], "settings": {"quota_budget_bytes": 500_000}}))
        .send()
        .await
        .unwrap();
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
}
