//! Private administration API: auth, endpoints, status, audit.
//!
//! HTTP-level behavior only: who may call, which statuses map to which
//! failures, and what the responses contain (or must never contain).
//! Domain logic underneath is covered in `policy.rs` and `store.rs`.

mod common;

use common::{
    admin_client, approve, endpoint_json, expect_close, get_settings, patch_settings,
    relay_connect, start, transfer, usage, HarnessOptions,
};
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::ClientBuilder,
    tls::{default_provider, CaTlsConfig},
};

async fn put_endpoint(
    h: &common::Harness,
    id: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    admin_client(&h.token)
        .put(format!("http://{}/admin/endpoints/{id}", h.admin_addr))
        .json(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn admin_rejects_unauthenticated_calls() {
    let h = start(HarnessOptions::default()).await;
    let anon = reqwest::Client::new();
    let base = format!("http://{}", h.admin_addr);
    for (method, path, body) in [
        ("GET", "/admin/endpoints", None),
        ("PUT", "/admin/endpoints/abc", Some(serde_json::json!({}))),
        ("POST", "/admin/endpoints/abc/revoke", None),
        ("GET", "/admin/status", None),
        ("GET", "/admin/metrics", None),
        ("GET", "/admin/usage", None),
    ] {
        let req = match (method, body) {
            ("GET", _) => anon.get(format!("{base}{path}")),
            ("PUT", Some(b)) => anon.put(format!("{base}{path}")).json(&b),
            _ => anon.post(format!("{base}{path}")),
        };
        assert_eq!(req.send().await.unwrap().status(), 401, "{method} {path}");
    }
}

#[tokio::test]
async fn admin_upsert_validates_and_conflicts() {
    let h = start(HarnessOptions::default()).await;
    // Unknown endpoint IDs and incoherent speed policies are 400s.
    assert_eq!(
        put_endpoint(&h, "not-a-key", &serde_json::json!({"label":"x"}))
            .await
            .status(),
        400
    );
    let id = SecretKey::generate().public().to_string();
    assert_eq!(
        put_endpoint(
            &h,
            &id,
            &serde_json::json!({"label":"a","approved":true,"speed_policy":"custom"})
        )
        .await
        .status(),
        400
    );
    assert_eq!(put_endpoint(&h, &id, &serde_json::json!({"label":"a","approved":true,"speed_policy":"unlimited","custom_rx_bps":1000})).await.status(), 400);

    // Create, then lost updates conflict.
    let r = put_endpoint(
        &h,
        &id,
        &serde_json::json!({"label":"dev <b>","approved":true}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<serde_json::Value>().await.unwrap()["revision"], 1);
    assert_eq!(
        put_endpoint(&h, &id, &serde_json::json!({"label":"second"}))
            .await
            .status(),
        409
    );
    assert_eq!(
        put_endpoint(
            &h,
            &id,
            &serde_json::json!({"label":"stale","revision":999})
        )
        .await
        .status(),
        409
    );
    let r = put_endpoint(&h, &id, &serde_json::json!({"label":"second","revision":1})).await;
    assert_eq!(r.status(), 200);
    let rec: serde_json::Value = r.json().await.unwrap();
    assert_eq!(rec["revision"], 2);
    assert_eq!(rec["label"], "second");

    // Labels are served raw to JSON but escaped for server-rendered contexts;
    // secrets never appear in the audit trail.
    let list: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/endpoints", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["endpoints"][0]["label_escaped"], "second");
    let audit: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/audit?limit=10", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!serde_json::to_string(&audit).unwrap().contains(&h.token));
}

#[tokio::test]
async fn admin_revoke_closes_live_but_spares_peers() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions::default()).await;
    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    let c_sk = SecretKey::generate();
    let c_id = c_sk.public();
    for (id, name) in [(a_id, "a"), (b_id, "b"), (c_id, "c")] {
        approve(&h, &id, serde_json::json!({"label": name})).await;
    }

    let mut a = relay_connect(h.relay_addr, a_sk).await;
    let mut b = relay_connect(h.relay_addr, b_sk).await;
    let mut c = relay_connect(h.relay_addr, c_sk).await;
    transfer(&mut b, &mut c, c_id, 3, 512).await; // baseline peers work

    let r = admin_client(&h.token)
        .post(format!(
            "http://{}/admin/endpoints/{a_id}/revoke",
            h.admin_addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["had_live_connections"],
        true
    );

    expect_close(&mut a, "revoked connection").await;
    transfer(&mut b, &mut c, c_id, 3, 512).await; // peers unaffected

    // Reconnect as the revoked identity is denied; the record shows it.
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .expect("tls");
    assert!(
        ClientBuilder::new(url, SecretKey::generate(), DnsResolver::new())
            .tls_client_config(tls)
            .connect()
            .await
            .is_err()
    );
    assert_eq!(endpoint_json(&h, &a_id).await["approved"], false);
}

#[tokio::test]
async fn admin_session_csrf_origin_and_settings() {
    let h = start(HarnessOptions::default()).await;
    let base = format!("http://{}", h.admin_addr);
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let r = client
        .post(format!("{base}/admin/login"))
        .json(&serde_json::json!({"token": h.token}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let csrf = r.json::<serde_json::Value>().await.unwrap()["csrf"]
        .as_str()
        .unwrap()
        .to_string();

    // Cookie alone reads; mutations need the CSRF header.
    assert_eq!(
        client
            .get(format!("{base}/admin/endpoints"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let id = SecretKey::generate().public().to_string();
    let r = client
        .put(format!("{base}/admin/endpoints/{id}"))
        .json(&serde_json::json!({"label":"x"}))
        .send()
        .await
        .unwrap();
    assert!(r.status() == 401 || r.status() == 403, "got {}", r.status());
    let r = client
        .put(format!("{base}/admin/endpoints/{id}"))
        .header("X-CSRF-Token", csrf.clone())
        .json(&serde_json::json!({"label":"x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Forged origins are rejected for cookie-authenticated mutations.
    let r = client
        .put(format!("{base}/admin/endpoints/{id}"))
        .header("X-CSRF-Token", csrf.clone())
        .header("Origin", "http://evil.example")
        .json(&serde_json::json!({"label":"y","revision":1}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Settings patches are versioned.
    let s = client
        .get(format!("{base}/admin/settings"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
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
    let r = admin_client(&h.token)
        .patch(format!("{base}/admin/settings"))
        .json(&serde_json::json!({"version": v, "settings": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
}

#[tokio::test]
async fn admin_status_usage_and_audit_shapes() {
    let h = start(HarnessOptions::default()).await;
    let st: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/status", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for key in [
        "service",
        "version",
        "db_ok",
        "live_connections",
        "approved_endpoints",
        "quota",
        "uptime_secs",
    ] {
        assert!(st.get(key).is_some(), "status missing {key}");
    }
    // No budget configured: explicit stub, never fake enforcement.
    let u = usage(&h).await;
    assert_eq!(u["implemented"], false);

    let s = get_settings(&h).await;
    let r = patch_settings(
        &h,
        s["version"].as_i64().unwrap(),
        serde_json::json!({"default_rx_bps": 5000}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let audit: serde_json::Value = admin_client(&h.token)
        .get(format!("http://{}/admin/audit?limit=5", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!audit["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn admin_metrics_are_bounded() {
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
    transfer(&mut a, &mut b, b_id, 5, 1024).await;

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
    // Bounded labels only: no endpoint IDs, IPs, or free-form content.
    assert!(!body.contains(&a_id.to_string()), "endpoint ID in metrics!");
    assert!(!body.contains("127.0.0.1"), "IP in metrics!");
    let _ = (a, b);
}

#[tokio::test]
async fn admin_rejects_oversize_bodies() {
    let h = start(HarnessOptions::default()).await;
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
}
