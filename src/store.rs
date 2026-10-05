//! SQLite durable store (Gate B).
//!
//! Single-writer, low-frequency admin path only. Admission hot path reads the
//! in-memory cache in `PolicyManager`, never SQLite.

use std::{path::Path, sync::Arc};

use tokio::sync::Mutex;

use crate::policy::EndpointPolicy;

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS endpoints (
  endpoint_id TEXT PRIMARY KEY,
  label TEXT NOT NULL DEFAULT '',
  approved INTEGER NOT NULL DEFAULT 0,
  speed_policy TEXT NOT NULL DEFAULT 'default',
  custom_rx_bps INTEGER NULL,
  custom_tx_bps INTEGER NULL,
  burst_bytes INTEGER NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS quota_periods (
  period TEXT PRIMARY KEY,
  budget_bytes INTEGER NOT NULL DEFAULT 0,
  charged_bytes INTEGER NOT NULL DEFAULT 0,
  exhausted INTEGER NOT NULL DEFAULT 0,
  warn75 INTEGER NOT NULL DEFAULT 0,
  warn90 INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#;

/// One monthly quota ledger row.
#[derive(Debug, Clone)]
pub struct QuotaRow {
    pub period: String,
    pub charged_bytes: u64,
    pub exhausted: bool,
    pub warn75: bool,
    pub warn90: bool,
}

/// Schema generation this binary understands. Bump when DDL changes;
/// opening a database with a newer generation fails closed.
pub const SCHEMA_GENERATION: u32 = 4;

#[derive(Debug)]
pub struct Store {
    conn: Mutex<rusqlite::Connection>,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Arc<Self>, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("db dir: {e:#}"))?;
            }
        }
        let conn = rusqlite::Connection::open(path).map_err(|e| format!("open db: {e:#}"))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| format!("busy_timeout: {e:#}"))?;
        // Fail closed on a database written by a newer binary.
        let generation: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|e| format!("user_version: {e:#}"))?;
        if generation > SCHEMA_GENERATION {
            return Err(format!(
                "database schema generation {generation} is newer than this binary ({SCHEMA_GENERATION}); refusing to open"
            ));
        }
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("migrate: {e:#}"))?;
        conn.execute(&format!("PRAGMA user_version = {SCHEMA_GENERATION}"), [])
            .map_err(|e| format!("stamp version: {e:#}"))?;
        // Seed settings version if absent.
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES ('settings_version','1')",
            [],
        )
        .map_err(|e| format!("seed: {e:#}"))?;
        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
        }))
    }

    /// Seed ordinary defaults from operator config when the DB has none.
    /// Never overrides values an admin already set.
    pub async fn ensure_defaults(
        &self,
        rx_bps: Option<u64>,
        tx_bps: Option<u64>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;
        if let Some(rx) = rx_bps {
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES ('default_rx_bps',?)",
                [rx.to_string()],
            )
            .map_err(|e| format!("seed rx: {e:#}"))?;
        }
        if let Some(tx) = tx_bps {
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES ('default_tx_bps',?)",
                [tx.to_string()],
            )
            .map_err(|e| format!("seed tx: {e:#}"))?;
        }
        Ok(())
    }

    /// Seed a single setting only when absent.
    pub async fn ensure_setting(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)",
            rusqlite::params![key, value],
        )
        .map_err(|e| format!("seed {key}: {e:#}"))?;
        Ok(())
    }

    /// Open (or create) the ledger row for a UTC month. Never deletes history.
    pub async fn open_period(&self, period: &str) -> Result<QuotaRow, String> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO quota_periods(period,budget_bytes,charged_bytes,exhausted,warn75,warn90,created_at,updated_at) VALUES (?,0,0,0,0,0,?,?)",
            rusqlite::params![period, now, now],
        )
        .map_err(|e| format!("open period: {e:#}"))?;
        Self::read_period_locked(&conn, period)
    }

    pub async fn read_period(&self, period: &str) -> Result<QuotaRow, String> {
        let conn = self.conn.lock().await;
        Self::read_period_locked(&conn, period)
    }

    fn read_period_locked(conn: &rusqlite::Connection, period: &str) -> Result<QuotaRow, String> {
        conn.query_row(
            "SELECT period,charged_bytes,exhausted,warn75,warn90 FROM quota_periods WHERE period=?",
            [period],
            |r| {
                Ok(QuotaRow {
                    period: r.get(0)?,
                    charged_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                    exhausted: r.get::<_, i32>(2)? != 0,
                    warn75: r.get::<_, i32>(3)? != 0,
                    warn90: r.get::<_, i32>(4)? != 0,
                })
            },
        )
        .map_err(|e| format!("read period: {e:#}"))
    }

    /// Durably move the charged counter. Positive = new grant (committed
    /// before the worker may spend); negative = proven-unspent return.
    /// Fails on storage error so the caller denies rather than overspending.
    pub async fn add_charged(&self, period: &str, delta: i64) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let conn = self.conn.lock().await;
        let n = conn
            .execute(
                "UPDATE quota_periods SET charged_bytes = max(0, charged_bytes + ?), updated_at=? WHERE period=?",
                rusqlite::params![delta, now, period],
            )
            .map_err(|e| format!("charge: {e:#}"))?;
        if n == 0 {
            return Err("period row missing".into());
        }
        Ok(())
    }

    pub async fn set_exhausted(&self, period: &str, exhausted: bool) {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let conn = self.conn.lock().await;
        let _ = conn.execute(
            "UPDATE quota_periods SET exhausted=?, updated_at=? WHERE period=?",
            rusqlite::params![exhausted as i32, now, period],
        );
    }

    pub async fn set_warn(&self, period: &str, pct: u8) {
        let col = if pct >= 90 { "warn90" } else { "warn75" };
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let conn = self.conn.lock().await;
        let _ = conn.execute(
            &format!("UPDATE quota_periods SET {col}=1, updated_at=? WHERE period=?"),
            rusqlite::params![now, period],
        );
    }

    /// Test/operator tooling: read the stamped schema generation.
    pub async fn user_version(&self) -> Result<u32, String> {
        let conn = self.conn.lock().await;
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|e| format!("user_version: {e:#}"))
    }

    /// Test/operator tooling: stamp a generation (e.g. to prove newer-DB
    /// refusal). Production never calls this.
    pub async fn set_user_version(&self, v: u32) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(&format!("PRAGMA user_version = {v}"), [])
            .map(|_| ())
            .map_err(|e| format!("stamp version: {e:#}"))
    }

    pub async fn upsert_endpoint(&self, e: &EndpointPolicy) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            r#"INSERT INTO endpoints(endpoint_id,label,approved,speed_policy,custom_rx_bps,custom_tx_bps,burst_bytes,revision,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(endpoint_id) DO UPDATE SET
                 label=excluded.label, approved=excluded.approved, speed_policy=excluded.speed_policy,
                 custom_rx_bps=excluded.custom_rx_bps, custom_tx_bps=excluded.custom_tx_bps,
                 burst_bytes=excluded.burst_bytes, revision=excluded.revision, updated_at=excluded.updated_at"#,
            rusqlite::params![
                e.endpoint_id,
                e.label,
                e.approved as i32,
                e.speed_policy.to_string(),
                e.custom_rx_bps,
                e.custom_tx_bps,
                e.burst_bytes,
                e.revision,
                e.created_at,
                e.updated_at,
            ],
        )
        .map_err(|e| format!("upsert: {e:#}"))?;
        Ok(())
    }

    fn row_to_endpoint(row: &rusqlite::Row) -> rusqlite::Result<EndpointPolicy> {
        let sp: String = row.get(3)?;
        Ok(EndpointPolicy {
            endpoint_id: row.get(0)?,
            label: row.get(1)?,
            approved: row.get::<_, i32>(2)? != 0,
            speed_policy: sp.parse().unwrap_or(crate::policy::SpeedPolicy::Default),
            custom_rx_bps: row.get(4)?,
            custom_tx_bps: row.get(5)?,
            burst_bytes: row.get(6)?,
            revision: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    }

    pub async fn list_endpoints(&self) -> Result<Vec<EndpointPolicy>, String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT endpoint_id,label,approved,speed_policy,custom_rx_bps,custom_tx_bps,burst_bytes,revision,created_at,updated_at FROM endpoints ORDER BY endpoint_id")
            .map_err(|e| format!("prepare: {e:#}"))?;
        let rows = stmt
            .query_map([], Self::row_to_endpoint)
            .map_err(|e| format!("query: {e:#}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("row: {e:#}"))?);
        }
        Ok(out)
    }

    pub async fn set_approved(
        &self,
        endpoint_id: &str,
        approved: bool,
    ) -> Result<EndpointPolicy, String> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let conn = self.conn.lock().await;
        let n = conn
            .execute(
                "UPDATE endpoints SET approved=?, revision=revision+1, updated_at=? WHERE endpoint_id=?",
                rusqlite::params![approved as i32, now, endpoint_id],
            )
            .map_err(|e| format!("revoke update: {e:#}"))?;
        if n == 0 {
            return Err("endpoint not found".into());
        }
        let mut stmt = conn
            .prepare("SELECT endpoint_id,label,approved,speed_policy,custom_rx_bps,custom_tx_bps,burst_bytes,revision,created_at,updated_at FROM endpoints WHERE endpoint_id=?")
            .map_err(|e| format!("prepare: {e:#}"))?;
        stmt.query_row([endpoint_id], Self::row_to_endpoint)
            .map_err(|e| format!("read back: {e:#}"))
    }

    pub async fn get_settings(&self) -> Result<(serde_json::Value, i64), String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT key, value FROM settings")
            .map_err(|e| format!("prepare: {e:#}"))?;
        let mut map = serde_json::Map::new();
        let mut version: i64 = 1;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| format!("query: {e:#}"))?;
        for r in rows {
            let (k, v) = r.map_err(|e| format!("row: {e:#}"))?;
            if k == "settings_version" {
                version = v.parse().unwrap_or(1);
            } else {
                // Try int, else string.
                if let Ok(n) = v.parse::<i64>() {
                    map.insert(k, serde_json::Value::from(n));
                } else if v.is_empty() {
                    map.insert(k, serde_json::Value::Null);
                } else {
                    map.insert(k, serde_json::Value::from(v));
                }
            }
        }
        Ok((serde_json::Value::Object(map), version))
    }

    /// Versioned patch: fails with conflict when `expected` != current.
    pub async fn patch_settings(
        &self,
        expected_version: i64,
        patch: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(serde_json::Value, i64), String> {
        let conn = self.conn.lock().await;
        let cur: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key='settings_version'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("version read: {e:#}"))?;
        let cur: i64 = cur.parse().unwrap_or(1);
        if cur != expected_version {
            return Err(format!(
                "settings revision conflict: expected {cur}, got {expected_version}"
            ));
        }
        for (k, v) in patch {
            if k == "settings_version" {
                continue;
            }
            // Validate known keys.
            if (k == "default_rx_bps" || k == "default_tx_bps") && !v.is_null() {
                let n = v
                    .as_i64()
                    .ok_or_else(|| format!("{k} must be integer or null"))?;
                if n <= 0 || n > 100_000_000_000 {
                    return Err(format!("{k} out of range"));
                }
            }
            if k == "quota_budget_bytes" && !v.is_null() {
                let n = v
                    .as_i64()
                    .ok_or_else(|| format!("{k} must be integer or null"))?;
                if n <= 0 {
                    return Err(format!("{k} must be positive"));
                }
            }
            if k == "quota_headroom_bytes" && !v.is_null() {
                let n = v
                    .as_i64()
                    .ok_or_else(|| format!("{k} must be integer or null"))?;
                if n < 0 {
                    return Err(format!("{k} must be >= 0"));
                }
            }
            if k == "quota_overhead_pct" && !v.is_null() {
                let n = v
                    .as_i64()
                    .ok_or_else(|| format!("{k} must be integer or null"))?;
                if !(0..=100).contains(&n) {
                    return Err(format!("{k} must be 0..=100"));
                }
            }
            if k == "quota_chunk_bytes" && !v.is_null() {
                let n = v
                    .as_i64()
                    .ok_or_else(|| format!("{k} must be integer or null"))?;
                if !(1_024..=1_048_576).contains(&n) {
                    return Err(format!("{k} must be 1024..=1048576"));
                }
            }
            if k == "alert_webhook_url" && !v.is_null() {
                let s = v
                    .as_str()
                    .ok_or_else(|| format!("{k} must be a string or null"))?;
                if s.len() > 512 || !(s.starts_with("http://") || s.starts_with("https://")) {
                    return Err(format!("{k} must be an http(s) URL <= 512 chars"));
                }
            }
            let s = match v {
                serde_json::Value::Null => String::new(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => return Err(format!("{k}: unsupported value type")),
            };
            conn.execute(
                "INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                rusqlite::params![k, s],
            )
            .map_err(|e| format!("patch: {e:#}"))?;
        }
        let next = cur + 1;
        conn.execute(
            "UPDATE settings SET value=? WHERE key='settings_version'",
            [next.to_string()],
        )
        .map_err(|e| format!("bump: {e:#}"))?;
        drop(conn);
        self.get_settings().await
    }

    pub async fn append_audit(&self, actor: &str, action: &str, target: &str, detail: &str) {
        let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let conn = self.conn.lock().await;
        let _ = conn.execute(
            "INSERT INTO audit(at,actor,action,target,detail) VALUES (?,?,?,?,?)",
            [at.as_str(), actor, action, target, detail],
        );
    }

    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<serde_json::Value>, String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT at,actor,action,target,detail FROM audit ORDER BY id DESC LIMIT ?")
            .map_err(|e| format!("prepare: {e:#}"))?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok(serde_json::json!({
                    "at": r.get::<_, String>(0)?,
                    "actor": r.get::<_, String>(1)?,
                    "action": r.get::<_, String>(2)?,
                    "target": r.get::<_, String>(3)?,
                    "detail": r.get::<_, String>(4)?,
                }))
            })
            .map_err(|e| format!("query: {e:#}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("row: {e:#}"))?);
        }
        Ok(out)
    }
}
