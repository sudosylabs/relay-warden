//! Shared per-endpoint throughput enforcement.
//!
//! Real relay traffic against small configured rates: sustained caps with
//! exact per-frame accounting, the shared aggregate across connections,
//! owner exemption with intact governance, live reshapes, reconnect reuse,
//! and independent directions. Deterministic bucket semantics (clocks,
//! debt, clamping) are unit-tested in `src/limiter.rs`.

mod common;

use std::time::Duration;

use common::{
    admin_client, approve, endpoint_json, relay_connect, start, transfer, Harness, HarnessOptions,
};
use iroh_base::SecretKey;

const RATE: u64 = 30_000; // B/s each direction for ordinary endpoints
const BURST: u64 = 4_096; // clamp(RATE/10, 4096, 1M)

async fn start_shaped() -> Harness {
    start(HarnessOptions {
        ordinary_limits: Some((RATE, RATE)),
        ..Default::default()
    })
    .await
}

#[tokio::test]
async fn limiter_caps_sustained_rate() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_shaped().await;
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
    let la = endpoint_json(&h, &a_id).await;
    let lb = endpoint_json(&h, &b_id).await;
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
async fn limiter_connections_share_allowance() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_shaped().await;
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

    let la = endpoint_json(&h, &a_id).await;
    assert!(
        la["limits"]["rx_bytes"].as_u64().unwrap() >= total as u64,
        "shared counter must cover both connections"
    );
}

#[tokio::test]
async fn limiter_unlimited_fast_but_still_governed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_shaped().await;
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();
    let d_sk = SecretKey::generate();
    let d_id = d_sk.public();
    approve(&h, &c_id, serde_json::json!({"speed_policy": "unlimited"})).await;
    approve(&h, &d_id, serde_json::json!({"speed_policy": "unlimited"})).await;

    let lc = endpoint_json(&h, &c_id).await;
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

    let lc = endpoint_json(&h, &c_id).await;
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
    common::expect_close(&mut c, "revoked owner connection").await;
    let _ = d;
}

#[tokio::test]
async fn limiter_live_update_reshapes_transfer() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_shaped().await;
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
    let cur = endpoint_json(&h, &a_id).await;
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
    let cur = endpoint_json(&h, &a_id).await;
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
async fn limiter_reconnect_keeps_balances() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_shaped().await;
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
    let before = endpoint_json(&h, &a_id).await;
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
    let after = endpoint_json(&h, &a_id).await;
    assert!(
        after["limits"]["rx_bytes"].as_u64().unwrap() >= rx_before + 6 * 2048,
        "counters must accumulate on the surviving limiter"
    );
}

#[tokio::test]
async fn limiter_directions_are_independent() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start_shaped().await;
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

    let la = endpoint_json(&h, &a_id).await;
    assert_eq!(la["limits"]["rx_bps"], serde_json::json!(15_000));
    assert_eq!(la["limits"]["tx_bps"], serde_json::Value::Null);

    // Download free: 22 x 2KiB back at loopback speed.
    let (down, _) = transfer(&mut b, &mut a, a_id, 22, 2048).await;
    assert!(
        down < Duration::from_secs(5),
        "download wrongly capped? {down:?}"
    );
}
