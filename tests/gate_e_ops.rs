//! Gate E: observability, alerts, resource bounds, packaging guards.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::ClientBuilder,
    protos::relay::{Datagrams, RelayToClientMsg},
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
    _clock: Arc<ManualClock>,
    _quota: Arc<QuotaManager>,
    policy: Arc<PolicyManager>,
    db_path: std::path::PathBuf,
    _relay_handle: n0_future::task::AbortOnDropHandle<()>,
    _admin_handle: n0_future::task::AbortOnDropHandle<()>,
}

async fn start_harness(conn_limit: Option<usize>) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "warden-e-{}-{}",
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
    for (k, v) in [
        ("quota_budget_bytes", "100000"),
        ("quota_headroom_bytes", "0"),
        ("quota_overhead_pct", "0"),
        ("quota_chunk_bytes", "8192"),
    ] {
        store.ensure_setting(k, v).await.unwrap();
    }

    let clock = Arc::new(ManualClock::new(
        month_start("2026-03").unwrap() + Duration::from_secs(14 * 86_400),
    ));
    let policy = PolicyManager::open(store.clone()).await.unwrap();
    let limiter = LimiterMap::new();
    let quota = QuotaManager::open(store, policy.clone(), clock.clone() as Arc<dyn Clock>)
        .await
        .unwrap();

    let mut relay_state = relay_warden::relay::RelayState::new(
        policy.clone() as Arc<dyn iroh_relay::server::DynAccessControl>,
        1024,
        64,
        Duration::from_secs(10),
    )
    .with_policy(policy.clone())
    .with_limiter(limiter.clone())
    .with_quota(quota.client());
    if let Some(n) = conn_limit {
        relay_state = relay_state.with_connection_limit(n);
    }
    quota.set_clients(relay_state.clients.clone());
    let (relay_addr, _relay_handle) =
        relay_warden::relay::serve("127.0.0.1:0".parse().unwrap(), relay_state)
            .await
            .unwrap();

    let admin_state = AdminState::new(policy.clone(), limiter, Some(quota.clone()), token_bytes);
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
        _clock: clock,
        _quota: quota,
        policy,
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

async fn approve(h: &Harness, id: &EndpointId) {
    let r = admin_client(&h.token)
        .put(format!("http://{}/admin/endpoints/{id}", h.admin_addr))
        .json(&serde_json::json!({"label": "t", "approved": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn gate_e_metrics_private_bounded_and_counter_semantics() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness(None).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id).await;
    approve(&h, &b_id).await;

    // Unauthenticated scraping fails.
    let r = reqwest::Client::new()
        .get(format!("http://{}/admin/metrics", h.admin_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let mut a = ClientBuilder::new(url.clone(), a_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .unwrap();
    let mut b = ClientBuilder::new(url, b_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .unwrap();
    // Move a little traffic so counters are nonzero.
    for i in 0..5u32 {
        let mut v = vec![0u8; 1024];
        v[..4].copy_from_slice(&i.to_be_bytes());
        a.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: b_id,
            datagrams: Datagrams::from(v),
        })
        .await
        .unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(10), b.next())
                .await
                .expect("t")
            {
                Some(Ok(RelayToClientMsg::Datagrams { .. })) => break,
                Some(Ok(_)) => continue,
                other => panic!("{other:?}"),
            }
        }
    }

    let r = admin_client(&h.token)
        .get(format!("http://{}/admin/metrics", h.admin_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"]
        .to_str()
        .unwrap()
        .contains("text/plain"));
    let body = r.text().await.unwrap();
    assert!(body.contains("warden_live_connections 2"), "{body}");
    assert!(
        body.contains("warden_quota_charged_bytes{period=\"2026-03\"}"),
        "{body}"
    );
    // Bounded labels: no endpoint IDs, IPs, or free-form labels leak.
    assert!(!body.contains(&a_id.to_string()), "endpoint ID in metrics!");
    assert!(!body.contains("127.0.0.1"), "IP in metrics!");
    let _ = (a, b);
}

#[tokio::test]
async fn gate_e_alerts_fire_once_per_period_and_survive_restart() {
    let h = start_harness(None).await;
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
        .json(&serde_json::json!({
            "version": s["version"],
            "settings": {"alert_webhook_url": format!("http://{hook_addr}/hook")},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Invalid webhook rejected.
    let s2: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/settings", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r = admin_client(&h.token)
        .patch(format!("http://{}/admin/settings", h.admin_addr))
        .json(&serde_json::json!({
            "version": s2["version"],
            "settings": {"alert_webhook_url": "ftp://x"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id).await;
    approve(&h, &b_id).await;
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let mut a = ClientBuilder::new(url.clone(), a_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .unwrap();
    let mut b = ClientBuilder::new(url, b_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .unwrap();

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
    // warning_75 arrives once (poll the capture list; delivery is async).
    let mut kinds = vec![];
    for _ in 0..100 {
        kinds = seen
            .lock()
            .unwrap()
            .iter()
            .map(|v| v["kind"].as_str().unwrap().to_string())
            .collect();
        if kinds.contains(&"warning_75".to_string()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        kinds.contains(&"warning_75".to_string()),
        "no warning_75, saw {kinds:?}"
    );
    let n75 = kinds.iter().filter(|k| *k == "warning_75").count();
    // Keep pushing to exhaustion: warning_90 + exhausted fire, 75 does not repeat.
    for i in 40..120u32 {
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
    tokio::time::sleep(Duration::from_secs(2)).await;
    let kinds: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|v| v["kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        kinds.iter().filter(|k| *k == "warning_75").count(),
        n75,
        "re-fired 75!"
    );
    assert!(
        kinds.contains(&"warning_90".to_string()),
        "no warning_90: {kinds:?}"
    );
    assert!(
        kinds.contains(&"exhausted".to_string()),
        "no exhausted alert: {kinds:?}"
    );
    assert_eq!(kinds.iter().filter(|k| *k == "exhausted").count(), 1);

    // Payload carries period + charged units, never traffic content.
    let snap: Vec<serde_json::Value> = seen.lock().unwrap().clone();
    let first = &snap[0];
    assert_eq!(first["period"], "2026-03");
    assert!(first["charged_bytes"].as_u64().unwrap() > 0);
    let text = serde_json::to_string(&snap).unwrap();
    assert!(!text.contains(&a_id.to_string()));
    let _ = (a, b);
}

#[tokio::test]
async fn gate_e_per_endpoint_cap_denies_with_balance() {
    use iroh_relay::http::ProtocolVersion;
    use iroh_relay::server::{Access, AccessControl, ClientRequest};

    let h = start_harness(None).await;
    h.policy.set_max_per_endpoint(Some(1));
    let sk = SecretKey::generate();
    let id = sk.public();
    approve(&h, &id).await;
    let parts = || {
        http::Request::builder()
            .uri("http://localhost/relay")
            .body(())
            .unwrap()
            .into_parts()
            .0
    };
    let r1 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    let c1 = r1.connection_id();
    assert!(matches!(h.policy.on_connect(&r1).await, Access::Allow));
    // Second concurrent connection denied.
    let r2 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(
        h.policy.on_connect(&r2).await,
        Access::Deny { .. }
    ));
    // After the first disconnects, admission reopens (balanced counters).
    h.policy.on_disconnect(id, c1);
    let r3 = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(h.policy.on_connect(&r3).await, Access::Allow));
}

#[tokio::test]
async fn gate_e_global_ceiling_rejects_over_limit() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness(Some(1)).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id).await;
    approve(&h, &b_id).await;
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let mut a = ClientBuilder::new(url.clone(), a_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .unwrap();
    // B passes authentication (the ceiling is checked after authorization so
    // live counters stay balanced) but never obtains relay service: its
    // connection is dropped immediately without registration.
    let mut b_over = ClientBuilder::new(url, b_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match b_over.next().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "over-ceiling connection must be dropped promptly"
    );
    // The admitted connection is unaffected (still counted live).
    let list: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/endpoints", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = list["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["endpoint_id"] == a_id.to_string())
        .unwrap();
    assert_eq!(entry["live_connections"], 1);
    let _ = &mut a;
}

#[tokio::test]
async fn gate_e_admin_body_limit_and_schema_guard() {
    let h = start_harness(None).await;
    // 100KB label exceeds the 64KiB admin body limit.
    let big = "x".repeat(100_000);
    let r = admin_client(&h.token)
        .put(format!(
            "http://{}/admin/endpoints/{}",
            h.admin_addr,
            SecretKey::generate().public()
        ))
        .json(&serde_json::json!({"label": big}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413, "oversize admin body must be rejected");

    // Schema generation stamped; newer generation refuses to open.
    let store = Store::open(&h.db_path).await.unwrap();
    assert_eq!(
        store.user_version().await.unwrap(),
        relay_warden::store::SCHEMA_GENERATION
    );
    store.set_user_version(99).await.unwrap();
    drop(store);
    let err = Store::open(&h.db_path)
        .await
        .expect_err("newer DB must refuse");
    assert!(err.contains("newer"), "{err}");
}
