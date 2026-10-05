//! Dev allowlist admission (legacy `AccessControl`).
//!
//! Direct decision tests: open vs closed, unknown denial, and the
//! per-endpoint ceiling with balanced counters.

use std::collections::HashSet;

use iroh_base::SecretKey;
use iroh_relay::{
    http::ProtocolVersion,
    server::{Access, AccessControl, ClientRequest},
};
use relay_warden::access::Allowlist;

fn parts() -> http::request::Parts {
    http::Request::builder()
        .uri("http://localhost/relay")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[tokio::test]
async fn access_open_admits_and_counts() {
    let list = Allowlist::open();
    let id = SecretKey::generate().public();
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
    let conn = req.connection_id();
    assert!(matches!(list.on_connect(&req).await, Access::Allow));
    assert_eq!(list.live_total(), 1);
    assert_eq!(
        list.admitted_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    list.on_disconnect(id, conn);
    assert_eq!(list.live_total(), 0);
}

#[tokio::test]
async fn access_closed_denies_unknown() {
    let keep = SecretKey::generate().public();
    let list = Allowlist::closed(HashSet::from([keep]));
    let req = ClientRequest::new(keep, ProtocolVersion::V2, parts());
    assert!(matches!(list.on_connect(&req).await, Access::Allow));

    let stranger = ClientRequest::new(SecretKey::generate().public(), ProtocolVersion::V2, parts());
    assert!(matches!(
        list.on_connect(&stranger).await,
        Access::Deny { .. }
    ));
    assert_eq!(
        list.denied_total.load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    list.allow(stranger.endpoint_id());
    let retry = ClientRequest::new(stranger.endpoint_id(), ProtocolVersion::V2, parts());
    assert!(matches!(list.on_connect(&retry).await, Access::Allow));
    list.deny(&stranger.endpoint_id());
    let retry = ClientRequest::new(stranger.endpoint_id(), ProtocolVersion::V2, parts());
    assert!(matches!(list.on_connect(&retry).await, Access::Deny { .. }));
}

#[tokio::test]
async fn access_ceiling_denies_with_balance() {
    let list = Allowlist::open();
    let id = SecretKey::generate().public();
    let mut conns = Vec::new();
    for _ in 0..16 {
        let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
        conns.push(req.connection_id());
        assert!(matches!(list.on_connect(&req).await, Access::Allow));
    }
    let over = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(list.on_connect(&over).await, Access::Deny { .. }));
    for c in conns {
        list.on_disconnect(id, c);
    }
    let req = ClientRequest::new(id, ProtocolVersion::V2, parts());
    assert!(matches!(list.on_connect(&req).await, Access::Allow));
}
