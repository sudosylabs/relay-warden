//! Tested client example: two endpoints, one relayed message each way.
//!
//! Generates two fresh endpoint identities, optionally approves them through
//! the admin API, then relays one datagram in each direction.
//!
//! ```sh
//! # Manual approval: print the IDs, approve them in the admin UI, then run.
//! cargo run --example relayed_transfer -- --relay http://127.0.0.1:8080
//! # Automatic approval for local testing (loopback only):
//! cargo run --example relayed_transfer -- --relay http://127.0.0.1:8080 \
//!   --admin http://127.0.0.1:8081 --admin-token "$(cat admin.token)"
//! ```

use std::time::Duration;

use clap::Parser;
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::ClientBuilder,
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    tls::{default_provider, CaTlsConfig},
};
use n0_future::{SinkExt, StreamExt};

#[derive(Debug, Parser)]
struct Args {
    /// Relay base URL, e.g. http://127.0.0.1:8080
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    relay: String,
    /// Admin base URL for automatic approval (testing only)
    #[arg(long)]
    admin: Option<String>,
    /// Admin bearer token (testing only; never commit this value)
    #[arg(long)]
    admin_token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let relay_url: RelayUrl = args.relay.parse()?;
    let tls = CaTlsConfig::default().client_config(default_provider())?;

    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    println!("endpoint A: {a_id}\nendpoint B: {b_id}");

    if let (Some(admin), Some(token)) = (args.admin, args.admin_token) {
        let http = reqwest::Client::new();
        for id in [a_id, b_id] {
            let r = http
                .put(format!("{admin}/admin/endpoints/{id}"))
                .bearer_auth(&token)
                .json(&serde_json::json!({"label": "example", "approved": true}))
                .send()
                .await?;
            if !r.status().is_success() {
                anyhow::bail!("approval failed for {id}: {}", r.status());
            }
        }
        println!("approved via admin API");
    } else {
        println!("approve both IDs in the admin interface (unapproved IDs are denied)");
    }

    let mut a = ClientBuilder::new(relay_url.clone(), a_sk, DnsResolver::new())
        .tls_client_config(tls.clone())
        .connect()
        .await?;
    let mut b = ClientBuilder::new(relay_url, b_sk, DnsResolver::new())
        .tls_client_config(tls)
        .connect()
        .await?;

    for (dst, word) in [(b_id, "hello"), (a_id, "howdy")] {
        let (tx, rx) = if dst == b_id {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        tx.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: dst,
            datagrams: Datagrams::from(word),
        })
        .await?;
        let msg = tokio::time::timeout(Duration::from_secs(10), rx.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("relay closed the connection"))??;
        match msg {
            RelayToClientMsg::Datagrams { datagrams, .. } => {
                println!("received: {}", String::from_utf8_lossy(&datagrams.contents));
            }
            other => anyhow::bail!("unexpected message: {other:?}"),
        }
    }
    println!("relayed transfer OK");
    Ok(())
}
