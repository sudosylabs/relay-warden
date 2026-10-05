//! Application-level coordinator.
//!
//! Multi-step updates live here — never scattered across HTTP handlers — so
//! every entry point (admin API today, any future control surface) preserves
//! the same invariants in the same order:
//!
//! - settings patch: atomic store commit, then audit, then refresh policy
//!   defaults into live limiters, then re-evaluate the quota ledger.
//! - endpoint write: canonicalizing CAS commit, then audit, then live
//!   limiter push, then disconnect when approval was removed.
//! - revocation: deny-first commit, then audit (disconnect happens inside
//!   the policy call, covering in-flight admissions via revalidation).

use std::{sync::Arc, time::Instant};

use crate::{
    limiter::LimiterMap,
    policy::{EndpointPolicy, EndpointUpsert, PolicyManager},
    quota::QuotaManager,
    store::Store,
};

#[derive(Debug, Clone)]
pub struct App {
    pub policy: Arc<PolicyManager>,
    pub limiter: Arc<LimiterMap>,
    pub quota: Option<Arc<QuotaManager>>,
    pub store: Arc<Store>,
}

impl App {
    pub fn new(
        policy: Arc<PolicyManager>,
        limiter: Arc<LimiterMap>,
        quota: Option<Arc<QuotaManager>>,
        store: Arc<Store>,
    ) -> Self {
        Self {
            policy,
            limiter,
            quota,
            store,
        }
    }

    /// Validate-and-commit a versioned settings patch, then propagate it to
    /// every runtime that reads settings. The store commit is atomic: a
    /// rejected patch changes nothing and refreshes nothing.
    pub async fn patch_settings(
        &self,
        expected_version: i64,
        patch: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(serde_json::Value, i64), String> {
        let (settings, version) = self.store.patch_settings(expected_version, patch).await?;
        self.store
            .append_audit("admin", "settings_patch", "", "")
            .await;
        // New ordinary defaults reshape live default-policy limiters.
        if let Ok(d) = self.policy.refresh_defaults().await {
            self.limiter
                .apply_all(&self.policy.list(), &d, Instant::now());
        }
        // New budget re-evaluates the ledger (may exhaust or reopen).
        if let Some(q) = &self.quota {
            q.refresh().await;
            self.store
                .append_audit("admin", "quota_reevaluated", "", "")
                .await;
        }
        Ok((settings, version))
    }

    /// Canonicalizing CAS endpoint write with live propagation.
    pub async fn upsert_endpoint(
        &self,
        endpoint_id: &str,
        input: &EndpointUpsert,
    ) -> Result<EndpointPolicy, String> {
        let rec = self.policy.upsert(endpoint_id, input).await?;
        self.store
            .append_audit("admin", "endpoint_upsert", &rec.endpoint_id, "")
            .await;
        // Push the new limits into the live limiter: no restart or
        // reconnect needed for the transfer to reshape.
        self.limiter
            .apply_record(&rec, &self.policy.defaults_snapshot(), Instant::now());
        // If approval was removed, disconnect live (same as revoke path).
        if !rec.approved {
            // Best-effort; post-register revalidation covers in-flight.
            if let Ok(id) = rec.endpoint_id.parse() {
                self.policy.revalidate(&id);
            }
        }
        Ok(rec)
    }

    /// Deny-first revocation with audit. Disconnection (existing plus
    /// in-flight via revalidation) happens inside the policy call.
    pub async fn revoke_endpoint(
        &self,
        endpoint_id: &str,
    ) -> Result<(EndpointPolicy, bool), String> {
        let (rec, had_live) = self.policy.revoke(endpoint_id).await?;
        self.store
            .append_audit("admin", "endpoint_revoke", &rec.endpoint_id, "")
            .await;
        Ok((rec, had_live))
    }
}
