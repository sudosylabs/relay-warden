//! Real public relay connections exercise the network guard through the adapter.
mod common;
use common::{approve, endpoint_json, relay_connect, start, transfer, HarnessOptions};
use iroh_base::SecretKey;
use relay_warden::network::NetworkConfig;
use std::time::Duration;

async fn assert_slow_transfer_completes(network: NetworkConfig, endpoint_rate: u64) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions {
        public_access: true,
        ordinary_limits: Some((endpoint_rate, endpoint_rate)),
        network: Some(network),
        ..Default::default()
    })
    .await;
    let a = SecretKey::generate();
    let a_id = a.public();
    let b = SecretKey::generate();
    let b_id = b.public();
    let mut a = relay_connect(h.relay_addr, a).await;
    let mut b = relay_connect(h.relay_addr, b).await;
    // An 8 KiB frame overdraws a 4 KiB burst at 1 KB/s. Every subsequent
    // frame waits longer than the upstream two-second whole-send timeout.
    // transfer checks exact payload contents and ordering, not just liveness.
    let (elapsed, bytes) = tokio::time::timeout(
        Duration::from_secs(30),
        transfer(&mut a, &mut b, b_id, 3, 8192),
    )
    .await
    .expect("slow transfer must complete");
    assert_eq!(bytes, 3 * 8192);
    assert!(
        elapsed > Duration::from_secs(8),
        "shaping was bypassed: {elapsed:?}"
    );
    let client = common::admin_client(&h.token);
    let status: serde_json::Value = client
        .get(format!("http://{}/admin/status", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        status["live_connections"], 2,
        "throttling disconnected a peer"
    );
    // The same connections remain usable after their sustained throttling.
    let (_, reply_bytes) = transfer(&mut b, &mut a, a_id, 1, 64).await;
    assert_eq!(reply_bytes, 64);
}

#[tokio::test]
async fn slow_ip_shaping_does_not_trigger_transport_timeout() {
    assert_slow_transfer_completes(
        NetworkConfig {
            ip_rx_bps: 1000,
            ip_tx_bps: 1000,
            ..Default::default()
        },
        1_000_000,
    )
    .await;
}

#[tokio::test]
async fn slow_prefix_shaping_does_not_trigger_transport_timeout() {
    assert_slow_transfer_completes(
        NetworkConfig {
            ipv4_prefix: Some(24),
            prefix_rx_bps: 1000,
            prefix_tx_bps: 1000,
            ..Default::default()
        },
        1_000_000,
    )
    .await;
}

#[tokio::test]
async fn slow_global_shaping_does_not_trigger_transport_timeout() {
    assert_slow_transfer_completes(
        NetworkConfig {
            global_rx_bps: 1000,
            global_tx_bps: 1000,
            ..Default::default()
        },
        1_000_000,
    )
    .await;
}

#[tokio::test]
async fn slow_endpoint_shaping_does_not_trigger_transport_timeout() {
    assert_slow_transfer_completes(NetworkConfig::default(), 1000).await;
}

#[tokio::test]
async fn revocation_interrupts_a_long_shaped_send() {
    use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
    use n0_future::{SinkExt, StreamExt};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions {
        public_access: true,
        ordinary_limits: Some((1_000_000, 1)),
        ..Default::default()
    })
    .await;
    let mut a = relay_connect(h.relay_addr, SecretKey::generate()).await;
    let b_key = SecretKey::generate();
    let b_id = b_key.public();
    approve(
        &h,
        &b_id,
        serde_json::json!({"speed_policy": "default", "burst_bytes": 4096}),
    )
    .await;
    let mut b = relay_connect(h.relay_addr, b_key).await;
    transfer(&mut a, &mut b, b_id, 1, 8192).await;
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: Datagrams::from(vec![0; 64]),
    })
    .await
    .unwrap();
    // The first frame exhausted the burst; the next cannot arrive for over
    // an hour at this rate. Revocation must not wait for that debt to refill.
    assert!(tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            match b.next().await {
                Some(Ok(RelayToClientMsg::Datagrams { .. })) => {
                    panic!("the second frame bypassed shaping")
                }
                Some(Ok(_)) => continue,
                other => panic!("connection closed before revocation: {other:?}"),
            }
        }
    })
    .await
    .is_err());
    let response = common::admin_client(&h.token)
        .post(format!(
            "http://{}/admin/endpoints/{b_id}/revoke",
            h.admin_addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    tokio::time::timeout(
        Duration::from_secs(1),
        common::expect_close(&mut b, "shaped send"),
    )
    .await
    .expect("revocation must interrupt shaping promptly");
}

#[tokio::test]
async fn unauthenticated_websockets_hold_source_capacity_and_headers_cannot_bypass_it() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = start(HarnessOptions {
        public_access: true,
        network: Some(NetworkConfig {
            max_connections_per_ip: 1,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    let mut socket = tokio::net::TcpStream::connect(h.relay_addr).await.unwrap();
    socket.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n", iroh_relay::http::RELAY_PATH, h.relay_addr).as_bytes()).await.unwrap();
    // The server can coalesce HTTP headers and a binary handshake frame in
    // one TCP read. Inspect only the fixed ASCII status prefix.
    let mut reply = [0; 12];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"HTTP/1.1 101");
    let response = reqwest::Client::new()
        .get(format!(
            "http://{}{}",
            h.relay_addr,
            iroh_relay::http::RELAY_PATH
        ))
        .header("x-forwarded-for", "192.0.2.1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
    drop(socket);
    // Source release is asynchronous; use the observed response as condition,
    // not a fixed sleep. An invalid request returns 400 once capacity is free.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let r = reqwest::Client::new()
                .get(format!(
                    "http://{}{}",
                    h.relay_addr,
                    iroh_relay::http::RELAY_PATH
                ))
                .send()
                .await
                .unwrap();
            if r.status() == 400 {
                break;
            }
            assert_eq!(r.status(), 429);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn public_identities_share_ip_bandwidth() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions {
        public_access: true,
        ordinary_limits: Some((1_000_000, 1_000_000)),
        network: Some(NetworkConfig {
            ip_rx_bps: 30_000,
            ip_tx_bps: 30_000,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    let a = SecretKey::generate();
    let b = SecretKey::generate();
    let b_id = b.public();
    let mut a = relay_connect(h.relay_addr, a).await;
    let mut b = relay_connect(h.relay_addr, b).await;
    let (elapsed, bytes) = transfer(&mut a, &mut b, b_id, 40, 2048).await;
    assert_eq!(bytes, 40 * 2048);
    assert!(
        elapsed >= Duration::from_secs_f64((bytes as f64 - 30_000.0) / 30_000.0 * 0.7),
        "IP shaping missing: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(15));
    let client = common::admin_client(&h.token);
    let observations: serde_json::Value = client
        .get(format!(
            "http://{}/admin/pending?page=1&limit=20",
            h.admin_addr
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(observations["mode"], "observed");
    assert_eq!(observations["requests"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn trusted_unlimited_is_scoped_to_identity_and_global_still_applies() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions {
        public_access: true,
        ordinary_limits: Some((1_000_000, 1_000_000)),
        network: Some(NetworkConfig {
            ip_rx_bps: 1,
            ip_tx_bps: 1,
            global_rx_bps: 30_000,
            global_tx_bps: 30_000,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    let a = SecretKey::generate();
    let a_id = a.public();
    let b = SecretKey::generate();
    let b_id = b.public();
    for id in [a_id, b_id] {
        approve(&h, &id, serde_json::json!({"speed_policy":"unlimited"})).await;
    }
    let mut a = relay_connect(h.relay_addr, a).await;
    let mut b = relay_connect(h.relay_addr, b).await;
    let (elapsed, bytes) = transfer(&mut a, &mut b, b_id, 40, 2048).await;
    assert_eq!(bytes, 40 * 2048);
    assert!(
        elapsed >= Duration::from_secs_f64((bytes as f64 - 30_000.0) / 30_000.0 * 0.7),
        "global shaping missing: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "IP exemption missing: {elapsed:?}"
    );
    assert!(
        endpoint_json(&h, &a_id).await["limits"]["rx_bytes"]
            .as_u64()
            .unwrap()
            >= bytes as u64
    );
}
