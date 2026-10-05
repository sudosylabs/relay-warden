//! relay-warden: private Iroh relay library.
//!
//! Gate A: minimal embedding of `iroh-relay` public APIs behind an Axum
//! frontend. Gate B: SQLite policy + live revocation + private admin.
//! Gate C: shared per-endpoint throughput enforcement.

pub mod access;
pub mod admin;
pub mod config;
pub mod limiter;
pub mod policy;
pub mod quota;
pub mod relay;
pub mod store;
