//! Relay embedding: protocol handling over public `iroh-relay` APIs.
//!
//! Covers the Axum frontend's responsibility only: relayed transfer between
//! real clients, subprotocol honesty, denial of unapproved identities, and
//! the global connection ceiling. Policy, shaping, and budget behavior live
//! in their own suites.

mod common;

use std::time::Duration;

use common::{approve, expect_close, relay_connect, start, HarnessOptions};
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::ClientBuilder,
    protos::{
        handshake,
        relay::{Datagrams, RelayToClientMsg},
    },
    tls::{default_provider, CaTlsConfig},
};
use n0_future::{SinkExt, StreamExt};

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
            return res.expect("stream item");
        }
    }
    panic!("no message received via relay");
}

#[tokio::test]
async fn relay_transfers_both_directions() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions::default()).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;

    let msg = Datagrams::from("hello b via warden");
    match send_recv(&mut a, &mut b, b_id, msg.clone()).await {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(remote_endpoint_id, a_id);
            assert_eq!(datagrams, msg);
        }
        other => panic!("unexpected {other:?}"),
    }
    let msg2 = Datagrams::from("howdy a via warden");
    match send_recv(&mut b, &mut a, a_id, msg2.clone()).await {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(remote_endpoint_id, b_id);
            assert_eq!(datagrams, msg2);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn relay_denies_unapproved_identity() {
    use iroh_relay::client::ConnectError;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions::default()).await;
    let allowed_sk = SecretKey::generate();
    approve(&h, &allowed_sk.public(), serde_json::json!({})).await;

    let relay_url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("tls");
    let err = ClientBuilder::new(relay_url.clone(), SecretKey::generate(), DnsResolver::new())
        .tls_client_config(tls.clone())
        .connect()
        .await
        .expect_err("unknown must be denied");
    assert!(
        matches!(
            err,
            ConnectError::Handshake {
                source: handshake::Error::ServerDeniedAuth { .. },
                ..
            }
        ),
        "expected ServerDeniedAuth, got {err:#}"
    );

    ClientBuilder::new(relay_url, allowed_sk, DnsResolver::new())
        .tls_client_config(tls)
        .connect()
        .await
        .expect("allowed connects");
}

#[tokio::test]
async fn relay_global_ceiling_drops_over_limit_without_service() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions {
        conn_limit: Some(1),
        ..Default::default()
    })
    .await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    approve(&h, &a_id, serde_json::json!({})).await;
    approve(&h, &b_id, serde_json::json!({})).await;

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    // B authenticates fine (the ceiling is checked after authorization so
    // live counters stay balanced) but never obtains relay service.
    let mut over = relay_connect(h.relay_addr, b_sk).await;
    expect_close(&mut over, "over-ceiling connection").await;

    // The admitted connection is unaffected (still counted live).
    let entry = common::endpoint_json(&h, &a_id).await;
    assert_eq!(entry["live_connections"], 1);
    let _ = &mut a;
}
