//! Startup configuration.
//!
//! Generic and self-hostable: no Oracle/Caddy/VPS assumptions. All addresses
//! default to loopback; public exposure is done by the operator's own reverse
//! proxy or listener config.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Application configuration, loadable from TOML and overridable by CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Loopback (or operator-chosen) address for the relay `/relay` endpoint.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Max unauthenticated handshakes in flight (bounded).
    #[serde(default = "default_max_handshakes")]
    pub max_handshake_concurrency: usize,
    /// Per-handshake timeout in seconds.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Key cache capacity for upstream `RelayedStream`.
    #[serde(default = "default_key_cache")]
    pub key_cache_capacity: usize,
    /// SQLite policy/accounting database path.
    #[serde(default = "default_db")]
    pub db_path: String,
    /// Private admin listen address (loopback by default; SSH tunnel for remote).
    #[serde(default = "default_admin_listen")]
    pub admin_listen: SocketAddr,
    /// Path to file containing the high-entropy admin token (restricted 0600).
    #[serde(default = "default_admin_token_file")]
    pub admin_token_file: String,
    /// Ordinary-endpoint default limits (bytes/sec). Required in production
    /// unless `require_default_limits` is explicitly disabled (tests/dev).
    #[serde(default)]
    pub default_rx_bps: Option<u64>,
    #[serde(default)]
    pub default_tx_bps: Option<u64>,
    #[serde(default = "default_require_limits")]
    pub require_default_limits: bool,
    /// Monthly budget (bytes). Required in production unless
    /// `require_quota_budget` is explicitly disabled (tests/dev).
    #[serde(default)]
    pub quota_budget_bytes: Option<u64>,
    #[serde(default)]
    pub quota_headroom_bytes: Option<u64>,
    #[serde(default)]
    pub quota_overhead_pct: Option<u64>,
    #[serde(default)]
    pub quota_chunk_bytes: Option<u64>,
    #[serde(default = "default_require_limits")]
    pub require_quota_budget: bool,
    /// Global concurrent relay-connection ceiling (Gate E DoS bound).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Per-endpoint concurrent connection ceiling (`None` = unbounded).
    #[serde(default = "default_max_per_endpoint")]
    pub max_connections_per_endpoint: Option<usize>,
    /// Optional webhook URL for quota threshold/exhaustion alerts.
    /// Disabled when unset.
    #[serde(default)]
    pub alert_webhook_url: Option<String>,
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8080".parse().expect("valid default")
}

fn default_max_handshakes() -> usize {
    64
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

fn default_key_cache() -> usize {
    1024
}

fn default_db() -> String {
    "warden.db".to_string()
}

fn default_admin_listen() -> SocketAddr {
    "127.0.0.1:8081".parse().expect("valid default")
}

fn default_admin_token_file() -> String {
    "admin.token".to_string()
}

fn default_require_limits() -> bool {
    true
}

fn default_max_connections() -> usize {
    1024
}

fn default_max_per_endpoint() -> Option<usize> {
    Some(16)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            max_handshake_concurrency: default_max_handshakes(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            key_cache_capacity: default_key_cache(),
            db_path: default_db(),
            admin_listen: default_admin_listen(),
            admin_token_file: default_admin_token_file(),
            default_rx_bps: None,
            default_tx_bps: None,
            require_default_limits: default_require_limits(),
            quota_budget_bytes: None,
            quota_headroom_bytes: None,
            quota_overhead_pct: None,
            quota_chunk_bytes: None,
            require_quota_budget: default_require_limits(),
            max_connections: default_max_connections(),
            max_connections_per_endpoint: default_max_per_endpoint(),
            alert_webhook_url: None,
        }
    }
}

impl Config {
    /// Minimal validation for fail-fast startup (Gate A).
    pub fn validate(&self) -> Result<(), String> {
        if self.max_handshake_concurrency == 0 {
            return Err("max_handshake_concurrency must be > 0".into());
        }
        if self.handshake_timeout_secs == 0 {
            return Err("handshake_timeout_secs must be > 0".into());
        }
        if self.key_cache_capacity == 0 {
            return Err("key_cache_capacity must be > 0".into());
        }
        if self.db_path.is_empty() {
            return Err("db_path must not be empty".into());
        }
        if self.admin_token_file.is_empty() {
            return Err("admin_token_file must not be empty".into());
        }
        for (name, v) in [
            ("default_rx_bps", self.default_rx_bps),
            ("default_tx_bps", self.default_tx_bps),
        ] {
            if let Some(n) = v {
                if n == 0 || n > 100_000_000_000 {
                    return Err(format!("{name} out of range"));
                }
            }
        }
        if let Some(n) = self.quota_budget_bytes {
            if n == 0 {
                return Err("quota_budget_bytes must be positive".into());
            }
        }
        if let Some(n) = self.quota_overhead_pct {
            if n > 100 {
                return Err("quota_overhead_pct must be 0..=100".into());
            }
        }
        if let Some(n) = self.quota_chunk_bytes {
            if !(1_024..=1_048_576).contains(&n) {
                return Err("quota_chunk_bytes must be 1024..=1048576".into());
            }
        }
        if self.max_connections == 0 {
            return Err("max_connections must be > 0".into());
        }
        if let Some(n) = self.max_connections_per_endpoint {
            if n == 0 {
                return Err("max_connections_per_endpoint must be > 0".into());
            }
        }
        if let Some(url) = &self.alert_webhook_url {
            if url.len() > 512 || !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err("alert_webhook_url must be an http(s) URL <= 512 chars".into());
            }
        }
        if self.listen.port() == 0 {
            // 0 is allowed for tests (OS-assigned), but warn in prod paths.
        }
        Ok(())
    }
}
