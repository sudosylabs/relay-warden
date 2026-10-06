//! relay-warden: policy-aware, self-hosted Iroh relay library.
//!
//! Axum frontend embedding public `iroh-relay` APIs, with SQLite-backed
//! endpoint policy and live revocation, a private admin API, shared
//! per-endpoint throughput enforcement, and a durable monthly outbound
//! budget. See `docs/ARCHITECTURE.md` for the architecture and `docs/ACCEPTANCE.md`
//! for the requirement mapping.

pub mod access;
pub mod admin;
pub mod admission;
pub mod config;
pub mod limiter;
pub mod network;
pub mod policy;
pub mod quota;
pub mod relay;
pub mod service;
pub mod store;
