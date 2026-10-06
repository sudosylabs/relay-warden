mod common;

use common::{admin_client, approve, expect_close, start, transfer, HarnessOptions, QuotaOpts};
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::client::{Client, ClientBuilder};
use relay_warden::admission::{AdmissionPolicy, Observations, MAX_OBSERVATIONS};

async fn connect(
    h: &common::Harness,
    key: SecretKey,
    token: Option<&str>,
) -> Result<Client, String> {
    let url: RelayUrl = format!("http://{}", h.relay_addr).parse().unwrap();
    let mut b =
        ClientBuilder::new(url, key, DnsResolver::new()).tls_client_config(common::tls_config());
    if let Some(t) = token {
        b = b.auth_token(t);
    }
    b.connect().await.map_err(|e| format!("{e:#}"))
}

async fn pending(h: &common::Harness) -> serde_json::Value {
    admin_client(&h.token)
        .get(format!("http://{}/admin/pending", h.admin_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[test]
fn token_checks_and_observations_are_bounded() {
    let p = AdmissionPolicy::new(true, Some(b"a-private-relay-token".to_vec()));
    assert!(!p.accepts_token(None));
    assert!(!p.accepts_token(Some("incorrect")));
    assert!(p.accepts_token(Some("a-private-relay-token")));
    assert!(!format!("{p:?}").contains("a-private-relay-token"));
    assert!(AdmissionPolicy::default().accepts_token(None));
    let mut o = Observations::default();
    for i in 0..MAX_OBSERVATIONS + 100 {
        o.record(i.to_string(), None);
    }
    assert_eq!(o.list().len(), MAX_OBSERVATIONS);
    o.record("0".into(), Some("192.0.2.1".parse().unwrap()));
    let row = o.get("0").unwrap();
    assert_eq!(row.attempts, 2);
    assert_eq!(row.observed_ip.unwrap().to_string(), "192.0.2.1");
    o.remove("0");
    assert!(o.get("0").is_none());
}

#[tokio::test]
async fn all_four_modes_and_pending_approval_flow() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    for public in [false, true] {
        for token_required in [false, true] {
            let token = "private-relay-access-token";
            let h = start(HarnessOptions {
                public_access: public,
                relay_token: token_required.then(|| token.to_owned()),
                ordinary_limits: Some((100_000, 200_000)),
                ..Default::default()
            })
            .await;
            let sk = SecretKey::generate();
            let id = sk.public();
            if token_required {
                assert!(connect(&h, sk.clone(), None).await.is_err());
                assert!(connect(&h, sk.clone(), Some("wrong")).await.is_err());
                assert_eq!(pending(&h).await["requests"], serde_json::json!([]));
                // An admin credential is not a relay credential.
                assert!(connect(&h, sk.clone(), Some(&h.token)).await.is_err());
            }
            let presented = token_required.then_some(token);
            let initial = connect(&h, sk.clone(), presented).await;
            if public {
                assert!(initial.is_ok());
                let p = pending(&h).await;
                assert_eq!(p["mode"], "observed");
                assert_eq!(p["requests"].as_array().unwrap().len(), 1);
                assert_eq!(p["requests"][0]["endpoint_id"], id.to_string());
                assert_eq!(p["requests"][0]["observed_ip"], "127.0.0.1");
                drop(initial);
            } else {
                assert!(initial.is_err());
                let p = pending(&h).await;
                assert_eq!(p["mode"], "requests");
                assert_eq!(p["requests"].as_array().unwrap().len(), 1);
                assert_eq!(p["requests"][0]["endpoint_id"], id.to_string());
                assert_eq!(p["requests"][0]["observed_ip"], "127.0.0.1");
                assert_eq!(p["requests"][0]["attempts"], 1);
                let anon = reqwest::Client::new();
                assert_eq!(
                    anon.get(format!("http://{}/admin/pending", h.admin_addr))
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    401
                );
                assert_eq!(
                    anon.post(format!(
                        "http://{}/admin/pending/{id}/dismiss",
                        h.admin_addr
                    ))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                    401
                );
                let c = admin_client(&h.token);
                assert_eq!(
                    c.post(format!(
                        "http://{}/admin/pending/{id}/dismiss",
                        h.admin_addr
                    ))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                    200
                );
                assert_eq!(pending(&h).await["requests"], serde_json::json!([]));
                assert!(connect(&h, sk.clone(), presented).await.is_err());
                approve(
                    &h,
                    &id,
                    serde_json::json!({"label":"Approved from request"}),
                )
                .await;
                assert_eq!(pending(&h).await["requests"], serde_json::json!([]));
            }
            let mut a = connect(&h, sk, presented).await.unwrap();
            let lim = h.limiter.get(&id.to_string()).unwrap();
            assert_eq!(lim.config().rx_bps, Some(100_000));
            assert_eq!(lim.config().tx_bps, Some(200_000));
            let settings = common::get_settings(&h).await;
            assert_eq!(
                common::patch_settings(
                    &h,
                    settings["version"].as_i64().unwrap(),
                    serde_json::json!({"default_rx_bps":300_000})
                )
                .await
                .status(),
                200
            );
            assert_eq!(lim.config().rx_bps, Some(300_000));
            let bsk = SecretKey::generate();
            let bid = bsk.public();
            if !public {
                approve(&h, &bid, serde_json::json!({})).await;
            }
            let mut b = connect(&h, bsk, presented).await.unwrap();
            transfer(&mut a, &mut b, bid, 2, 512).await;
            // Unknown devices obey defaults; observed identity never carries a token.
            let st: serde_json::Value = admin_client(&h.token)
                .get(format!("http://{}/admin/status", h.admin_addr))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(
                st["access_policy"],
                serde_json::json!({"token_required":token_required,"approval_required":!public})
            );
            assert!(!pending(&h).await.to_string().contains(token));
            if public {
                approve(&h, &id, serde_json::json!({})).await;
            }
            assert_eq!(
                admin_client(&h.token)
                    .post(format!(
                        "http://{}/admin/endpoints/{id}/revoke",
                        h.admin_addr
                    ))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                200
            );
            expect_close(&mut a, "revocation in access mode").await;
        }
    }
}

#[tokio::test]
async fn public_unsaved_connections_stop_at_monthly_budget() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = start(HarnessOptions {
        public_access: true,
        quota: Some(QuotaOpts {
            budget: 10_000,
            chunk: 1024,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    let mut c = connect(&h, SecretKey::generate(), None).await.unwrap();
    assert!(h.quota.as_ref().unwrap().acquire(10_000).await);
    assert!(!h.quota.as_ref().unwrap().acquire(1).await);
    expect_close(&mut c, "unsaved public endpoint at quota exhaustion").await;
    assert!(connect(&h, SecretKey::generate(), None).await.is_err());
}
