use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use clap::Parser;
use relay_warden::{
    admin, config::Config, limiter::LimiterMap, policy::PolicyManager, quota::QuotaManager, relay,
    store::Store,
};
use tracing_subscriber::EnvFilter;

/// relay-warden: private Iroh relay (Gate D: monthly budget enforcement).
#[derive(Debug, Parser)]
struct Args {
    /// Relay listen address, e.g. 127.0.0.1:8080. Overrides config file.
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// Admin listen address, e.g. 127.0.0.1:8081. Overrides config file.
    #[arg(long)]
    admin_listen: Option<SocketAddr>,
    /// Optional TOML config file.
    #[arg(long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let mut cfg = if let Some(path) = args.config.as_deref() {
        let text = std::fs::read_to_string(path)?;
        toml::from_str::<Config>(&text)?
    } else {
        Config::default()
    };
    if let Some(listen) = args.listen {
        cfg.listen = listen;
    }
    if let Some(admin_listen) = args.admin_listen {
        cfg.admin_listen = admin_listen;
    }
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;

    let store = Store::open(Path::new(&cfg.db_path))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    // Seed ordinary defaults from config file (never overrides admin values).
    store
        .ensure_defaults(cfg.default_rx_bps, cfg.default_tx_bps)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    // Seed quota settings from config file (never overrides admin values).
    if let Some(b) = cfg.quota_budget_bytes {
        store
            .ensure_setting("quota_budget_bytes", &b.to_string())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(x) = cfg.quota_headroom_bytes {
        store
            .ensure_setting("quota_headroom_bytes", &x.to_string())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(x) = cfg.quota_overhead_pct {
        store
            .ensure_setting("quota_overhead_pct", &x.to_string())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(x) = cfg.quota_chunk_bytes {
        store
            .ensure_setting("quota_chunk_bytes", &x.to_string())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(url) = &cfg.alert_webhook_url {
        store
            .ensure_setting("alert_webhook_url", url)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    let policy = PolicyManager::open(store.clone())
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    policy.set_max_per_endpoint(cfg.max_connections_per_endpoint);

    // Fail fast when ordinary limits are unconfigured (production default).
    let defaults = policy.defaults_snapshot();
    if cfg.require_default_limits && (defaults.rx_bps.is_none() || defaults.tx_bps.is_none()) {
        anyhow::bail!(
            "ordinary default limits are not configured (default_rx_bps/default_tx_bps). \
             Set them in the config file or via PATCH /admin/settings before production startup, \
             or set require_default_limits = false for local tests."
        );
    }

    // Fail closed when the secret file is missing (no default password).
    let token = admin::load_admin_token(&cfg.admin_token_file).map_err(|e| anyhow::anyhow!(e))?;

    let limiter = LimiterMap::new();
    let mut relay_state = relay::RelayState::new(
        policy.clone() as Arc<dyn iroh_relay::server::DynAccessControl>,
        cfg.key_cache_capacity,
        cfg.max_handshake_concurrency,
        Duration::from_secs(cfg.handshake_timeout_secs),
    )
    .with_policy(policy.clone())
    .with_limiter(limiter.clone())
    .with_connection_limit(cfg.max_connections);
    let relay_clients = relay_state.clients.clone();

    // Monthly budget gate (absent when unconfigured and not required).
    let quota = {
        let (settings, _) = store.get_settings().await.map_err(|e| anyhow::anyhow!(e))?;
        let qcfg = relay_warden::quota::QuotaConfig::from_settings(&settings);
        if qcfg.budget_bytes.is_none() && cfg.require_quota_budget {
            anyhow::bail!(
                "monthly relay budget is not configured (quota_budget_bytes). \
                 Set it in the config file or via PATCH /admin/settings before production startup, \
                 or set require_quota_budget = false for local tests."
            );
        }
        if qcfg.budget_bytes.is_some() {
            let q = QuotaManager::open(
                store.clone(),
                policy.clone(),
                Arc::new(relay_warden::quota::SystemClock),
            )
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
            q.set_clients(relay_clients.clone());
            relay_state = relay_state.with_quota(q.client());
            Some(q)
        } else {
            None
        }
    };

    let (relay_addr, _relay_handle) = relay::serve(cfg.listen, relay_state)
        .await
        .map_err(|e| anyhow::anyhow!("relay serve: {e:#}"))?;

    let admin_state = admin::AdminState::new(policy, limiter.clone(), quota.clone(), token);
    let admin_app = admin::router(admin_state);
    let admin_listener = tokio::net::TcpListener::bind(cfg.admin_listen).await?;
    let admin_addr = admin_listener.local_addr()?;
    tracing::info!(%relay_addr, %admin_addr, "relay-warden listening (Gate D)");
    axum::serve(
        admin_listener,
        admin_app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    // Graceful shutdown: wake throttled tasks, drain relay connections
    // (returns proven-unspent lease remainders), then stop the ledger actor.
    limiter.wake_all();
    relay_clients.shutdown().await;
    if let Some(q) = quota {
        q.shutdown().await;
    }
    Ok(())
}
