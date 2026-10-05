//! Startup configuration validation.
//!
//! Fail-fast operator feedback: every bound the binary enforces at boot is
//! asserted here, so misconfiguration surfaces before any socket opens.

use relay_warden::config::Config;

fn valid() -> Config {
    Config {
        require_default_limits: false,
        require_quota_budget: false,
        ..Default::default()
    }
}

#[test]
fn config_defaults_validate() {
    assert!(valid().validate().is_ok());
}

#[test]
fn config_rejects_empty_hot_paths() {
    let mut c = valid();
    c.max_handshake_concurrency = 0;
    assert!(c.validate().is_err());
    let mut c = valid();
    c.handshake_timeout_secs = 0;
    assert!(c.validate().is_err());
    let mut c = valid();
    c.key_cache_capacity = 0;
    assert!(c.validate().is_err());
    let mut c = valid();
    c.db_path = String::new();
    assert!(c.validate().is_err());
    let mut c = valid();
    c.admin_token_file = String::new();
    assert!(c.validate().is_err());
    let mut c = valid();
    c.max_connections = 0;
    assert!(c.validate().is_err());
    let mut c = valid();
    c.max_connections_per_endpoint = Some(0);
    assert!(c.validate().is_err());
}

#[test]
fn config_rejects_out_of_range_rates() {
    let mut c = valid();
    c.default_rx_bps = Some(0);
    assert!(c.validate().is_err());
    let mut c = valid();
    c.default_tx_bps = Some(100_000_000_001);
    assert!(c.validate().is_err());
    let mut c = valid();
    c.quota_budget_bytes = Some(0);
    assert!(c.validate().is_err());
    let mut c = valid();
    c.quota_overhead_pct = Some(101);
    assert!(c.validate().is_err());
    let mut c = valid();
    c.quota_chunk_bytes = Some(512);
    assert!(c.validate().is_err());
    let mut c = valid();
    c.alert_webhook_url = Some("ftp://x".into());
    assert!(c.validate().is_err());
    let mut c = valid();
    c.alert_webhook_url = Some("https://hooks.example.com/warden".into());
    assert!(c.validate().is_ok());
}
