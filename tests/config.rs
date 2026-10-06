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
    assert!(!valid().require_endpoint_approval);
    assert!(valid().relay_token_file.is_none());
}

#[test]
fn relay_token_config_must_be_separate_and_nonempty() {
    let mut c = valid();
    c.relay_token_file = Some(String::new());
    assert!(c.validate().is_err());
    c.relay_token_file = Some(c.admin_token_file.clone());
    assert!(c.validate().is_err());
    c.relay_token_file = Some("relay.token".into());
    assert!(c.validate().is_ok());
    c.require_endpoint_approval = false;
    assert!(c.validate().is_ok());
}

#[test]
fn binary_refuses_missing_short_or_reused_relay_token() {
    let dir =
        std::env::temp_dir().join(format!("warden-token-validation-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let admin = dir.join("admin.token");
    let relay = dir.join("relay.token");
    std::fs::write(&admin, "private-admin-token-for-test").unwrap();
    for content in [None, Some("short"), Some("private-admin-token-for-test")] {
        if let Some(value) = content {
            std::fs::write(&relay, value).unwrap();
        }
        let cfg = Config {
            admin_token_file: admin.to_str().unwrap().into(),
            relay_token_file: Some(relay.to_str().unwrap().into()),
            db_path: dir.join("warden.db").to_str().unwrap().into(),
            ..valid()
        };
        let path = dir.join("config.toml");
        std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_relay-warden"))
            .args(["--config", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("relay token") || stderr.contains("must be different"),
            "{stderr}"
        );
        assert!(!stderr.contains("private-admin-token-for-test"));
    }
}

#[test]
fn shipped_configurations_parse_and_keep_production_guards() {
    for text in [
        include_str!("../deploy/config.local.example.toml"),
        include_str!("../deploy/config.production.example.toml"),
    ] {
        let config: Config = toml::from_str(text).unwrap();
        config.validate().unwrap();
        assert!(config.require_default_limits && config.require_quota_budget);
        assert!(config.listen.ip().is_loopback() && config.admin_listen.ip().is_loopback());
        assert!(config.default_rx_bps.unwrap() > 0 && config.default_tx_bps.unwrap() > 0);
        assert!(config.quota_budget_bytes.unwrap() > config.quota_headroom_bytes.unwrap());
    }
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
