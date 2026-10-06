//! Tested client example: two endpoints, one relayed message each way.
//!
//! Generates two fresh endpoint identities, optionally approves them through
//! the admin API, then relays one datagram in each direction.
//!
//! ```sh
//! # Manual approval: approve the printed IDs in the UI, then press Enter.
//! cargo run --example relayed_transfer -- --relay http://127.0.0.1:8080
//! # Automatic approval for local testing (loopback only):
//! cargo run --example relayed_transfer -- --relay http://127.0.0.1:8080 \
//!   --admin http://127.0.0.1:8081 --admin-token-file admin.token
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
    /// File containing the admin bearer token (avoids secrets in process args)
    #[arg(long, requires = "admin")]
    admin_token_file: Option<std::path::PathBuf>,
    /// File containing the separate relay-access token, when required
    #[arg(long)]
    relay_token_file: Option<std::path::PathBuf>,
    /// Try connecting before waiting, so devices appear under Access requests
    #[arg(long, conflicts_with = "admin")]
    request_access: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let relay_url: RelayUrl = args.relay.parse()?;
    let tls = CaTlsConfig::default().client_config(default_provider())?;
    let relay_token = args
        .relay_token_file
        .map(std::fs::read_to_string)
        .transpose()?
        .map(|s| s.trim().to_owned());

    let a_sk = SecretKey::generate();
    let a_id = a_sk.public();
    let b_sk = SecretKey::generate();
    let b_id = b_sk.public();
    println!("endpoint A: {a_id}\nendpoint B: {b_id}");

    if let (Some(admin), Some(token_file)) = (args.admin, args.admin_token_file) {
        let admin_url: reqwest::Url = admin.parse()?;
        let loopback = admin_url.host_str().is_some_and(|h| {
            h == "localhost"
                || h.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        anyhow::ensure!(
            loopback && admin_url.scheme() == "http",
            "automatic approval requires a loopback HTTP admin URL (use an SSH tunnel)"
        );
        let token = std::fs::read_to_string(token_file)?;
        let http = reqwest::Client::new();
        for id in [a_id, b_id] {
            let r = http
                .put(format!("{admin}/admin/endpoints/{id}"))
                .bearer_auth(token.trim())
                .json(&serde_json::json!({"label": "example", "approved": true}))
                .send()
                .await?;
            if !r.status().is_success() {
                anyhow::bail!("approval failed for {id}: {}", r.status());
            }
        }
        println!("approved via admin API");
    } else {
        if args.request_access {
            for sk in [a_sk.clone(), b_sk.clone()] {
                let mut builder = ClientBuilder::new(relay_url.clone(), sk, DnsResolver::new())
                    .tls_client_config(tls.clone());
                if let Some(t) = &relay_token {
                    builder = builder.auth_token(t);
                }
                match builder.connect().await {
                    Ok(client) => { drop(client); println!("endpoint already has relay access"); }
                    Err(_) => println!("connection refused; check Access requests (a valid relay token is required when enabled)"),
                }
            }
        }
        if args.request_access {
            println!("If approval is required, approve both IDs in the admin interface. Press Enter to connect.");
            let mut line = String::new();
            anyhow::ensure!(
                std::io::stdin().read_line(&mut line)? > 0,
                "confirmation required"
            );
        }
    }

    let mut a_builder = ClientBuilder::new(relay_url.clone(), a_sk, DnsResolver::new())
        .tls_client_config(tls.clone());
    let mut b_builder =
        ClientBuilder::new(relay_url, b_sk, DnsResolver::new()).tls_client_config(tls);
    if let Some(t) = &relay_token {
        a_builder = a_builder.auth_token(t);
        b_builder = b_builder.auth_token(t);
    }
    let mut a = a_builder.connect().await?;
    let mut b = b_builder.connect().await?;

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
                anyhow::ensure!(
                    datagrams.contents.as_ref() == word.as_bytes(),
                    "relay payload differs from what was sent"
                );
                println!("received: {}", String::from_utf8_lossy(&datagrams.contents));
            }
            other => anyhow::bail!("unexpected message: {other:?}"),
        }
    }
    println!("relayed transfer OK");
    Ok(())
}
