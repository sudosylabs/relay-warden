//! Gate B: persistent policy, auth admin, live revocation.

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
    policy::PolicyManager,
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
    _relay_handle: n0_future::task::AbortOnDropHandle<()>,
    _admin_handle: n0_future::task::AbortOnDropHandle<()>,
    policy: Arc<PolicyManager>,
    db_path: std::path::PathBuf,
}

async fn start_harness() -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "warden-b-{}-{}",
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
    let policy = PolicyManager::open(store).await.unwrap();

    let limiter = relay_warden::limiter::LimiterMap::new();
    let relay_state = relay_warden::relay::RelayState::new(
        policy.clone() as Arc<dyn iroh_relay::server::DynAccessControl>,
        1024,
        64,
        Duration::from_secs(10),
    )
    .with_policy(policy.clone())
    .with_limiter(limiter.clone());
    let (relay_addr, _relay_handle) =
        relay_warden::relay::serve("127.0.0.1:0".parse().unwrap(), relay_state)
            .await
            .unwrap();

    let admin_state = AdminState::new(policy.clone(), limiter, None, token_bytes);
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

    // Re-serve relay handle leak guard: _relay_handle keeps the server task
    // alive (AbortOnDropHandle aborts on drop).
    Harness {
        relay_addr,
        admin_addr,
        token,
        _relay_handle,
        _admin_handle,
        policy,
        db_path,
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

async fn put_endpoint(
    admin_addr: SocketAddr,
    token: &str,
    id: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    admin_client(token)
        .put(format!("http://{admin_addr}/admin/endpoints/{id}"))
        .json(body)
        .send()
        .await
        .unwrap()
}

async fn relay_connect(relay_addr: SocketAddr, sk: SecretKey) -> iroh_relay::client::Client {
    let url: RelayUrl = format!("http://{relay_addr}").parse().unwrap();
    ClientBuilder::new(url, sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect("relay connect")
}

async fn send_recv(
    tx: &mut iroh_relay::client::Client,
    rx: &mut iroh_relay::client::Client,
    dst: EndpointId,
    msg: Datagrams,
) -> RelayToClientMsg {
    for _ in 0..20 {
        tx.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: dst,
            datagrams: msg.clone(),
        })
        .await
        .expect("send");
        if let Ok(Some(res)) = tokio::time::timeout(Duration::from_millis(500), rx.next()).await {
            return res.expect("item");
        }
    }
    panic!("no relay message");
}

#[tokio::test]
async fn gate_b_unauthorized_fails() {
    let h = start_harness().await;
    let anon = reqwest::Client::new();
    let r = anon
        .get(format!("http://{}/admin/endpoints", h.admin_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = anon
        .put(format!("http://{}/admin/endpoints/abc", h.admin_addr))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = anon
        .post(format!(
            "http://{}/admin/endpoints/abc/revoke",
            h.admin_addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn gate_b_upsert_validation_and_lost_update() {
    let h = start_harness().await;
    // Invalid endpoint ID.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        "not-a-key",
        &serde_json::json!({"label":"x"}),
    )
    .await;
    assert_eq!(r.status(), 400);

    let sk = SecretKey::generate();
    let id = sk.public().to_string();
    // Custom without bps -> 400.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"a","approved":true,"speed_policy":"custom"}),
    )
    .await;
    assert_eq!(r.status(), 400);
    // Unlimited with custom bps -> 400.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"a","approved":true,"speed_policy":"unlimited","custom_rx_bps":1000}),
    )
    .await;
    assert_eq!(r.status(), 400);

    // Valid create.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"dev <b>","approved":true}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let rec: serde_json::Value = r.json().await.unwrap();
    assert_eq!(rec["revision"], 1);

    // Update without revision -> 409.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"second"}),
    )
    .await;
    assert_eq!(r.status(), 409);

    // Stale revision -> 409.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"stale","revision":999}),
    )
    .await;
    assert_eq!(r.status(), 409);

    // Correct revision ok.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"second","revision":1}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let rec: serde_json::Value = r.json().await.unwrap();
    assert_eq!(rec["revision"], 2);
    assert_eq!(rec["label"], "second");

    // Label escaping exposed; raw label intact; no secret leakage in audit.
    let list: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/endpoints", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ep = &list["endpoints"][0];
    assert_eq!(ep["label_escaped"], "second");
    let audit: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/audit?limit=10", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let text = serde_json::to_string(&audit).unwrap();
    assert!(!text.contains(&h.token), "token leaked into audit");
}

#[tokio::test]
async fn gate_b_revoke_closes_live_and_denies_reconnect() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await;

    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();

    for (id, name) in [(a_id, "a"), (b_id, "b"), (c_id, "c")] {
        let r = put_endpoint(
            h.admin_addr,
            &h.token,
            &id.to_string(),
            &serde_json::json!({"label":name,"approved":true}),
        )
        .await;
        assert_eq!(r.status(), 200, "{name} approve failed");
    }

    let mut a = relay_connect(h.relay_addr, a_sk.clone()).await;
    let mut b = relay_connect(h.relay_addr, b_sk.clone()).await;
    let mut c = relay_connect(h.relay_addr, c_sk.clone()).await;

    // Baseline b -> c works.
    let msg = Datagrams::from("before");
    let got = send_recv(&mut b, &mut c, c_id, msg.clone()).await;
    assert!(matches!(got, RelayToClientMsg::Datagrams { .. }));

    // Revoke a.
    let r = admin_client(&h.token)
        .post(format!(
            "http://{}/admin/endpoints/{}/revoke",
            h.admin_addr, a_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["had_live_connections"], true);

    // a's connection must close promptly.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match a.next().await {
                None => break,
                Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "revoked connection did not close");

    // b <-> c still work.
    let msg2 = Datagrams::from("after");
    let got2 = send_recv(&mut b, &mut c, c_id, msg2.clone()).await;
    match got2 {
        RelayToClientMsg::Datagrams { datagrams, .. } => assert_eq!(datagrams, msg2),
        other => panic!("unexpected {other:?}"),
    }

    // Reconnect with the same revoked key must be denied.
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let err = ClientBuilder::new(url.clone(), a_sk.clone(), DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect_err("revoked must be denied");
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("Denied")
            || dbg.contains("denied")
            || format!("{err:#}").contains("not authorized"),
        "got {err:?}"
    );
    // Unknown key also denied (closed policy).
    let unk = SecretKey::generate();
    let err2 = ClientBuilder::new(url, unk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect_err("unknown denied");
    let _ = format!("{err2:?}");
    // Policy shows a unapproved.
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
        .expect("a listed");
    assert_eq!(entry["approved"], false);
}

#[tokio::test]
async fn gate_b_admission_cache_and_live_counts() {
    use iroh_relay::http::ProtocolVersion;
    use iroh_relay::server::{Access, AccessControl, ClientRequest};

    let h = start_harness().await;
    let sk = SecretKey::generate();
    let id = sk.public();
    let parts = http::Request::builder()
        .uri("http://localhost/relay")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    // Unknown -> deny (closed policy), no live count.
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts);
    let conn_id = req.connection_id();
    assert!(matches!(
        h.policy.on_connect(&req).await,
        Access::Deny { .. }
    ));
    assert_eq!(h.policy.live_count(&id.to_string()), 0);

    // Approve via admin, then admission allows and tracks live.
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id.to_string(),
        &serde_json::json!({"label":"live","approved":true}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let parts2 = http::Request::builder()
        .uri("http://localhost/relay")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let req2 = ClientRequest::new(id, ProtocolVersion::V2, parts2);
    let conn2 = req2.connection_id();
    assert!(matches!(h.policy.on_connect(&req2).await, Access::Allow));
    assert_eq!(h.policy.live_count(&id.to_string()), 1);

    // Revoke publishes synchronously: later admissions deny immediately.
    h.policy.revoke(&id.to_string()).await.unwrap();
    let parts3 = http::Request::builder()
        .uri("http://localhost/relay")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let req3 = ClientRequest::new(id, ProtocolVersion::V2, parts3);
    assert!(matches!(
        h.policy.on_connect(&req3).await,
        Access::Deny { .. }
    ));

    // Disconnect balances the earlier allow.
    h.policy.on_disconnect(id, conn2);
    h.policy.on_disconnect(id, conn_id); // never admitted: no-op
    assert_eq!(h.policy.live_count(&id.to_string()), 0);
}

#[tokio::test]
async fn gate_b_persists_across_restart() {
    let h = start_harness().await;
    let sk = SecretKey::generate();
    let id = sk.public().to_string();
    let r = put_endpoint(
        h.admin_addr,
        &h.token,
        &id,
        &serde_json::json!({"label":"persist","approved":true,"speed_policy":"unlimited"}),
    )
    .await;
    assert_eq!(r.status(), 200);

    // Reopen same db file in a fresh manager (simulates restart).
    let store2 = Store::open(&h.db_path).await.unwrap();
    let policy2 = PolicyManager::open(store2).await.unwrap();
    let rec = policy2.get(&id).expect("persisted");
    assert_eq!(rec.label, "persist");
    assert!(rec.approved);
    assert_eq!(rec.revision, 1);
}

#[tokio::test]
async fn gate_b_session_csrf_and_settings_version() {
    let h = start_harness().await;
    let base = format!("http://{}", h.admin_addr);
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    // Login.
    let r = client
        .post(format!("{base}/admin/login"))
        .json(&serde_json::json!({"token": h.token}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    let csrf = body["csrf"].as_str().expect("csrf").to_string();

    // Cookie auth without CSRF: GET ok, PUT rejected.
    let r = client
        .get(format!("{base}/admin/endpoints"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let sk = SecretKey::generate();
    let id = sk.public().to_string();
    let r = client
        .put(format!("{base}/admin/endpoints/{id}"))
        .json(&serde_json::json!({"label":"x"}))
        .send()
        .await
        .unwrap();
    assert!(r.status() == 401 || r.status() == 403, "got {}", r.status());

    // With CSRF ok.
    let r = client
        .put(format!("{base}/admin/endpoints/{id}"))
        .header("X-CSRF-Token", csrf.clone())
        .json(&serde_json::json!({"label":"x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Bad origin rejected for cookie mutation.
    let r = client
        .put(format!("{base}/admin/endpoints/{id}"))
        .header("X-CSRF-Token", csrf.clone())
        .header("Origin", "http://evil.example")
        .json(&serde_json::json!({"label":"y","revision":1}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Settings versioned patch.
    let s: serde_json::Value = client
        .get(format!("{base}/admin/settings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let v = s["version"].as_i64().unwrap();
    let r = client
        .patch(format!("{base}/admin/settings"))
        .header("X-CSRF-Token", csrf)
        .json(&serde_json::json!({"version": v, "settings": {"default_rx_bps": 1000}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Stale version conflicts.
    let r = admin_client(&h.token)
        .patch(format!("{base}/admin/settings"))
        .json(&serde_json::json!({"version": v, "settings": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
}
