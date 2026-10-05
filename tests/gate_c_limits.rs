//! Gate C: shared per-endpoint throughput enforcement.
//!
//! Timing bounds are one-sided on purpose: token math cannot go faster than
//! the configured rate on any machine (lower bounds catch missing shaping),
//! while upper bounds are generous (slow CI only makes shaping slower).
//! Byte-counter assertions are exact up to framing overhead.

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

const RATE: u64 = 30_000; // B/s each direction for ordinary endpoints
const BURST: u64 = 4_096; // clamp(RATE/10, 4096, 1M)

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
}

async fn start_harness() -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "warden-c-{}-{}",
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
    store.ensure_defaults(Some(RATE), Some(RATE)).await.unwrap();
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

    let admin_state = AdminState::new(policy, limiter, None, token_bytes);
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

/// Sequence-numbered payload: first 4 bytes BE seq, rest pad.
fn payload(seq: u32, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    v[..4].copy_from_slice(&seq.to_be_bytes());
    v
}

fn seq_of(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().unwrap())
}

/// Blast `n` messages, collect in order. Returns (elapsed, total_payload).
async fn transfer(
    tx: &mut iroh_relay::client::Client,
    rx: &mut iroh_relay::client::Client,
    dst: EndpointId,
    n: usize,
    size: usize,
) -> (Duration, usize) {
    let start = std::time::Instant::now();
    for i in 0..n {
        tx.send(iroh_relay::protos::relay::ClientToRelayMsg::Datagrams {
            dst_endpoint_id: dst,
            datagrams: Datagrams::from(payload(i as u32, size)),
        })
        .await
        .expect("send");
    }
    let mut got = Vec::with_capacity(n);
    let deadline = Duration::from_secs(90);
    while got.len() < n {
        let elapsed = start.elapsed();
        assert!(
            elapsed < deadline,
            "transfer stalled after {elapsed:?} ({}/{n})",
            got.len()
        );
        let next = tokio::time::timeout(deadline - elapsed, rx.next()).await;
        match next {
            Ok(Some(Ok(RelayToClientMsg::Datagrams { datagrams, .. }))) => {
                got.push(seq_of(&datagrams.contents));
            }
            Ok(Some(Ok(_))) => continue, // Status/health: ignore.
            Ok(Some(Err(e))) => panic!("recv error: {e:#}"),
            Ok(None) => panic!("connection closed mid-transfer"),
            Err(_) => panic!("transfer timed out"),
        }
    }
    for (i, s) in got.iter().enumerate() {
        assert_eq!(*s, i as u32, "frame order violated at index {i}");
    }
    (start.elapsed(), n * size)
}

async fn endpoint_limits(h: &Harness, id: &EndpointId) -> serde_json::Value {
    let list: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/endpoints", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    list["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["endpoint_id"] == id.to_string())
        .cloned()
        .expect("endpoint listed")
}

#[tokio::test]
async fn gate_c_caps_sustained_rate() {
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

    // 45 x 2KiB = 92160 payload bytes; both ends burst 4096.
    let (elapsed, bytes) = transfer(&mut a, &mut b, b_id, 45, 2048).await;
    let floor = Duration::from_secs_f64((bytes as u64 - 2 * BURST) as f64 / RATE as f64 * 0.7);
    assert!(
        elapsed >= floor,
        "too fast ({elapsed:?} < {floor:?}): shaping missing?"
    );
    assert!(elapsed < Duration::from_secs(45), "too slow: {elapsed:?}");

    // Counters: exactly one charge per frame direction (payload + framing).
    let la = endpoint_limits(&h, &a_id).await;
    let lb = endpoint_limits(&h, &b_id).await;
    let a_rx = la["limits"]["rx_bytes"].as_u64().unwrap();
    let b_tx = lb["limits"]["tx_bytes"].as_u64().unwrap();
    for (name, v) in [("a.rx", a_rx), ("b.tx", b_tx)] {
        assert!(
            v >= bytes as u64 && v - (bytes as u64) < 45 * 128,
            "{} = {}, payload {}: double-count or miscount?",
            name,
            v,
            bytes
        );
    }
    assert!(
        la["limits"]["throttled_bytes"].as_u64().unwrap() > 0,
        "expected observed throttle delay"
    );
}

#[tokio::test]
async fn gate_c_connections_share_allowance() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;

    // Two connections, same endpoint A (second deactivates the first; both
    // still send through the shared rx bucket).
    let mut a1 = relay_connect(h.relay_addr, a_sk.clone()).await;
    let mut a2 = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    let start = std::time::Instant::now();
    // Sequential legs share the depletion: a2 inherits a1's empty bucket.
    // (Concurrent legs share it too; sequential keeps the proof deterministic.)
    let (e1, b1) = transfer(&mut a1, &mut b, b_id, 22, 2048).await;
    let (e2, b2) = transfer(&mut a2, &mut b, b_id, 23, 2048).await;
    let total = b1 + b2; // 92160
    let wall = start.elapsed();
    let _ = (e1, e2);
    // Aggregate, not 2x: full 90KiB through one 30KB/s bucket.
    let floor = Duration::from_secs_f64((total as u64 - 2 * BURST) as f64 / RATE as f64 * 0.7);
    assert!(
        wall >= floor,
        "too fast ({wall:?} < {floor:?}): per-connection limits?"
    );
    assert!(wall < Duration::from_secs(60), "too slow: {wall:?}");

    let la = endpoint_limits(&h, &a_id).await;
    assert!(
        la["limits"]["rx_bytes"].as_u64().unwrap() >= total as u64,
        "shared counter must cover both connections"
    );
}

#[tokio::test]
async fn gate_c_unlimited_fast_but_still_governed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await;
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();
    let d_sk = SecretKey::generate();
    let d_id = d_sk.public();
    approve(&h, &c_id, serde_json::json!({"speed_policy": "unlimited"})).await;
    approve(&h, &d_id, serde_json::json!({"speed_policy": "unlimited"})).await;

    let lc = endpoint_limits(&h, &c_id).await;
    // No limiter yet (lazy on connect); after connect both directions null.
    assert!(lc["limits"]["rx_bps"].is_null() || lc["limits"].get("note").is_some());

    let mut c = relay_connect(h.relay_addr, c_sk).await;
    let mut d = relay_connect(h.relay_addr, d_sk).await;
    // 150 x 2KiB = 307200 bytes unshaped: loopback does this in ~1s.
    let (elapsed, _) = transfer(&mut c, &mut d, d_id, 150, 2048).await;
    assert!(
        elapsed < Duration::from_secs(10),
        "unlimited should be fast: {elapsed:?}"
    );

    let lc = endpoint_limits(&h, &c_id).await;
    assert_eq!(lc["limits"]["rx_bps"], serde_json::Value::Null);
    assert_eq!(lc["limits"]["tx_bps"], serde_json::Value::Null);

    // Approval still applies to unlimited endpoints: revoke disconnects.
    let r = admin_client(&h.token)
        .post(format!(
            "http://{}/admin/endpoints/{c_id}/revoke",
            h.admin_addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match c.next().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "revoked owner connection did not close");
}

#[tokio::test]
async fn gate_c_live_update_reshapes_transfer() {
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

    // Shaped baseline: 30 x 2KiB.
    let (t1, _) = transfer(&mut a, &mut b, b_id, 30, 2048).await;
    assert!(
        t1 >= Duration::from_secs_f64(1.0),
        "baseline not shaped? {t1:?}"
    );

    // Lift A's cap mid-stream (needs current revision).
    let cur = endpoint_limits(&h, &a_id).await;
    let rev = cur["revision"].as_i64().unwrap();
    let r = admin_client(&h.token)
        .put(format!("http://{}/admin/endpoints/{a_id}", h.admin_addr))
        .json(&serde_json::json!({"speed_policy": "unlimited", "revision": rev}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // B's tx still caps at RATE: use an unlimited peer for the fast leg.
    let u_sk = SecretKey::generate();
    let u_id = u_sk.public();
    approve(&h, &u_id, serde_json::json!({"speed_policy": "unlimited"})).await;
    let mut u = relay_connect(h.relay_addr, u_sk).await;
    let (t2, _) = transfer(&mut a, &mut u, u_id, 30, 2048).await;
    assert!(t2 < Duration::from_secs(5), "lifted cap still slow? {t2:?}");

    // Re-impose a custom cap on A: slow again, no reconnect.
    let cur = endpoint_limits(&h, &a_id).await;
    let rev = cur["revision"].as_i64().unwrap();
    let r = admin_client(&h.token)
        .put(format!("http://{}/admin/endpoints/{a_id}", h.admin_addr))
        .json(&serde_json::json!({"speed_policy": "custom", "custom_rx_bps": RATE as i64, "revision": rev}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let (t3, _) = transfer(&mut a, &mut u, u_id, 30, 2048).await;
    assert!(
        t3 >= Duration::from_secs_f64(1.0),
        "re-imposed cap not shaping? {t3:?}"
    );
}

#[tokio::test]
async fn gate_c_reconnect_keeps_balances() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;
    let mut a = relay_connect(h.relay_addr, a_sk.clone()).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    // Drain both buckets with 30 x 2KiB.
    transfer(&mut a, &mut b, b_id, 30, 2048).await;
    // Reconnect immediately: no idle window, so no refill can hide a mint.
    // (Refill-with-time is correct behavior; the no-mint property is also
    // proven without time in limiter::tests::limiter_reconnect_reuses_balances.)
    drop(a);

    // Same limiter object survives the reconnect (counters prove it).
    let before = endpoint_limits(&h, &a_id).await;
    let rx_before = before["limits"]["rx_bytes"].as_u64().unwrap();
    assert!(rx_before >= 30 * 2048);

    let mut a2 = relay_connect(h.relay_addr, a_sk).await;
    // Small probe on empty buckets: fully paced, no fresh burst.
    let start = std::time::Instant::now();
    transfer(&mut a2, &mut b, b_id, 6, 2048).await;
    assert!(
        start.elapsed() >= Duration::from_millis(250),
        "fresh burst minted on reconnect?"
    );
    let after = endpoint_limits(&h, &a_id).await;
    assert!(
        after["limits"]["rx_bytes"].as_u64().unwrap() >= rx_before + 6 * 2048,
        "counters must accumulate on the surviving limiter"
    );
}

#[tokio::test]
async fn gate_c_directions_are_independent() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_harness().await;
    // A: slow upload, free download. B: free both ways.
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(
        &h,
        &a_id,
        serde_json::json!({"speed_policy": "custom", "custom_rx_bps": 15_000}),
    )
    .await;
    approve(&h, &b_id, serde_json::json!({"speed_policy": "unlimited"})).await;

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    // Upload throttled by A.rx = 15KB/s: 22 x 2KiB.
    let (up, _) = transfer(&mut a, &mut b, b_id, 22, 2048).await;
    assert!(
        up >= Duration::from_secs_f64(1.5),
        "upload not capped? {up:?}"
    );

    let la = endpoint_limits(&h, &a_id).await;
    assert_eq!(la["limits"]["rx_bps"], serde_json::json!(15_000));
    assert_eq!(la["limits"]["tx_bps"], serde_json::Value::Null);
    let _ = la;

    // Download free: 22 x 2KiB back at loopback speed.
    let (down, _) = transfer(&mut b, &mut a, a_id, 22, 2048).await;
    assert!(
        down < Duration::from_secs(5),
        "download wrongly capped? {down:?}"
    );
    let _ = la;
}
