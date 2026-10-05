//! Gate A: two real clients transfer through our relay; unapproved denied.
//!
//! Uses `iroh-relay` client transport directly (relay-only), so no direct
//! P2P path exists in the harness — traffic must flow via `Clients` registry.

use std::{collections::HashSet, sync::Arc, time::Duration};

use iroh_base::{RelayUrl, SecretKey};
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
use rand::{RngExt, SeedableRng};
use relay_warden::{access::Allowlist, relay::RelayState};

async fn test_state_open() -> (std::net::SocketAddr, RelayState) {
    let access: Arc<dyn iroh_relay::server::DynAccessControl> = Arc::new(Allowlist::open());
    let state = RelayState::new(access, 1024, 64, Duration::from_secs(10));
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound, _h) = relay_warden::relay::serve(addr, state.clone())
        .await
        .expect("serve");
    // keep task alive via leaked handle? serve returns AbortOnDropHandle;
    // for tests we forget it so the server stays up for the test duration.
    std::mem::forget(_h);
    (bound, state)
}

fn tls_config() -> rustls::ClientConfig {
    CaTlsConfig::default()
        .client_config(default_provider())
        .expect("tls")
}

async fn send_recv(
    tx: &mut iroh_relay::client::Client,
    rx: &mut iroh_relay::client::Client,
    dst: iroh_base::EndpointId,
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
async fn gate_a_two_clients_relay() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (addr, _state) = test_state_open().await;
    let relay_url: RelayUrl = format!("http://{addr}").parse().unwrap();

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
    let a_sk = SecretKey::from_bytes(&rng.random());
    let a_id = a_sk.public();
    let b_sk = SecretKey::from_bytes(&rng.random());
    let b_id = b_sk.public();

    let mut a = ClientBuilder::new(relay_url.clone(), a_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect("a connect");
    let mut b = ClientBuilder::new(relay_url.clone(), b_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect("b connect");

    // a -> b
    let msg = Datagrams::from("hello b via warden");
    let got = send_recv(&mut a, &mut b, b_id, msg.clone()).await;
    match got {
        RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } => {
            assert_eq!(remote_endpoint_id, a_id);
            assert_eq!(datagrams, msg);
        }
        other => panic!("unexpected {other:?}"),
    }

    // b -> a
    let msg2 = Datagrams::from("howdy a via warden");
    let got2 = send_recv(&mut b, &mut a, a_id, msg2.clone()).await;
    match got2 {
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
async fn gate_a_unknown_denied() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let allowed_sk = SecretKey::generate();
    let allowed_id = allowed_sk.public();
    let mut set = HashSet::new();
    set.insert(allowed_id);
    let access: Arc<dyn iroh_relay::server::DynAccessControl> = Arc::new(Allowlist::closed(set));
    let state = RelayState::new(access, 1024, 64, Duration::from_secs(10));
    let (bound, _h) = relay_warden::relay::serve("127.0.0.1:0".parse().unwrap(), state)
        .await
        .expect("serve");
    std::mem::forget(_h);
    let relay_url: RelayUrl = format!("http://{bound}").parse().unwrap();

    // Unknown endpoint must fail handshake with ServerDeniedAuth.
    let unknown_sk = SecretKey::generate();
    let err = ClientBuilder::new(relay_url.clone(), unknown_sk, DnsResolver::new())
        .tls_client_config(tls_config())
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

    // Allowed endpoint still connects.
    let _ok = ClientBuilder::new(relay_url, allowed_sk, DnsResolver::new())
        .tls_client_config(tls_config())
        .connect()
        .await
        .expect("allowed connects");
}
