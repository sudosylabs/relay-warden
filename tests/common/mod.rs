//! Shared integration-test harness.
//!
//! One builder for every suite: each `tests/<module>.rs` file exercises a
//! single `src/` module's responsibility through the smallest surface that
//! proves it (direct calls for pure logic, HTTP for the admin API, real relay
//! clients for traffic behavior).

// Compiled into every integration binary, each using only a subset.
#![allow(dead_code)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::ClientBuilder,
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
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

pub const TEST_MONTH: &str = "2026-03";

#[derive(Debug, Clone, Default)]
pub struct QuotaOpts {
    pub budget: u64,
    pub headroom: u64,
    pub overhead: u64,
    pub chunk: u64,
}

#[derive(Debug, Clone, Default)]
pub struct HarnessOptions {
    /// Ordinary (default-policy) throughput limits. `None` = unconfigured.
    pub ordinary_limits: Option<(u64, u64)>,
    /// Monthly budget gate. `None` = disabled (passthrough).
    pub quota: Option<QuotaOpts>,
    /// Global concurrent-connection ceiling. `None` = unbounded.
    pub conn_limit: Option<usize>,
    /// Per-endpoint ceiling override. `None` = leave compiled default.
    pub max_per_endpoint: Option<Option<usize>>,
}

pub struct Harness {
    pub relay_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub token: String,
    pub quota: Option<Arc<QuotaManager>>,
    pub clock: Option<Arc<ManualClock>>,
    pub db_path: PathBuf,
    _relay_handle: n0_future::task::AbortOnDropHandle<()>,
    _admin_handle: n0_future::task::AbortOnDropHandle<()>,
}

pub async fn start(opts: HarnessOptions) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "warden-t-{}-{}",
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
    if let Some((rx, tx)) = opts.ordinary_limits {
        store.ensure_defaults(Some(rx), Some(tx)).await.unwrap();
    }
    if let Some(q) = &opts.quota {
        for (k, v) in [
            ("quota_budget_bytes", q.budget.to_string()),
            ("quota_headroom_bytes", q.headroom.to_string()),
            ("quota_overhead_pct", q.overhead.to_string()),
            ("quota_chunk_bytes", q.chunk.to_string()),
        ] {
            store.ensure_setting(k, &v).await.unwrap();
        }
    }

    let clock = opts.quota.as_ref().map(|_| {
        Arc::new(ManualClock::new(
            month_start(TEST_MONTH).unwrap() + Duration::from_secs(14 * 86_400),
        ))
    });
    let policy = PolicyManager::open(store.clone()).await.unwrap();
    if let Some(cap) = opts.max_per_endpoint {
        policy.set_max_per_endpoint(cap);
    }
    let limiter = LimiterMap::new();
    let quota = match (&opts.quota, &clock) {
        (Some(_), Some(clock)) => Some(
            QuotaManager::open(store, policy.clone(), clock.clone() as Arc<dyn Clock>)
                .await
                .unwrap(),
        ),
        _ => None,
    };

    let mut relay_state = relay_warden::relay::RelayState::new(
        policy.clone() as Arc<dyn iroh_relay::server::DynAccessControl>,
        1024,
        64,
        Duration::from_secs(10),
    )
    .with_policy(policy.clone())
    .with_limiter(limiter.clone());
    if let Some(q) = &quota {
        relay_state = relay_state.with_quota(q.client());
    }
    if let Some(n) = opts.conn_limit {
        relay_state = relay_state.with_connection_limit(n);
    }
    if let Some(q) = &quota {
        q.set_clients(relay_state.clients.clone());
    }
    let (relay_addr, _relay_handle) =
        relay_warden::relay::serve("127.0.0.1:0".parse().unwrap(), relay_state)
            .await
            .unwrap();

    let admin_state = AdminState::new(policy.clone(), limiter.clone(), quota.clone(), token_bytes);
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
        quota,
        clock,
        db_path,
        _relay_handle,
        _admin_handle,
    }
}

pub fn tls_config() -> rustls::ClientConfig {
    CaTlsConfig::default()
        .client_config(default_provider())
        .expect("tls")
}

pub fn admin_client(token: &str) -> reqwest::Client {
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

/// Approve an endpoint, merging `extra` policy fields over label+approved.
pub async fn approve(h: &Harness, id: &EndpointId, extra: serde_json::Value) {
    let mut map = serde_json::Map::new();
    map.insert("label".into(), "t".into());
    map.insert("approved".into(), true.into());
    if let serde_json::Value::Object(extra) = extra {
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

pub async fn relay_connect(relay_addr: SocketAddr, sk: SecretKey) -> iroh_relay::client::Client {
    let url: RelayUrl = format!("http://{relay_addr}").parse().unwrap();
    ClientBuilder::new(url, sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect("relay connect")
}

/// Sequence-numbered payload: first 4 bytes BE seq, rest pad.
pub fn payload(seq: u32, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    v[..4].copy_from_slice(&seq.to_be_bytes());
    v
}

pub fn seq_of(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().unwrap())
}

/// Blast `n` messages then collect them in order. Returns (elapsed, payload).
pub async fn transfer(
    tx: &mut iroh_relay::client::Client,
    rx: &mut iroh_relay::client::Client,
    dst: EndpointId,
    n: usize,
    size: usize,
) -> (Duration, usize) {
    let start = std::time::Instant::now();
    for i in 0..n {
        tx.send(ClientToRelayMsg::Datagrams {
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
            "transfer stalled ({}/{} in {elapsed:?})",
            got.len(),
            n
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

/// Drain `rx` until the connection closes. Returns (messages, payload bytes).
pub async fn recv_until_close(rx: &mut iroh_relay::client::Client) -> (usize, usize) {
    let mut n = 0usize;
    let mut bytes = 0usize;
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(30), rx.next()).await {
        match msg {
            Ok(RelayToClientMsg::Datagrams { datagrams, .. }) => {
                n += 1;
                bytes += datagrams.contents.len();
            }
            _ => break, // closed / error / timeout: relay stopped
        }
    }
    (n, bytes)
}

/// Wait until `rx` closes (revoke/exhaustion/ceiling path).
pub async fn expect_close(rx: &mut iroh_relay::client::Client, what: &str) {
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.next().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "{what} did not close promptly");
}

pub async fn usage(h: &Harness) -> serde_json::Value {
    admin_client(&h.token)
        .get(format!("http://{}/admin/usage", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

pub async fn endpoint_json(h: &Harness, id: &EndpointId) -> serde_json::Value {
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

pub async fn get_settings(h: &Harness) -> serde_json::Value {
    admin_client(&h.token)
        .get(format!("http://{}/admin/settings", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

pub async fn patch_settings(
    h: &Harness,
    version: i64,
    settings: serde_json::Value,
) -> reqwest::Response {
    admin_client(&h.token)
        .patch(format!("http://{}/admin/settings", h.admin_addr))
        .json(&serde_json::json!({"version": version, "settings": settings}))
        .send()
        .await
        .unwrap()
}
