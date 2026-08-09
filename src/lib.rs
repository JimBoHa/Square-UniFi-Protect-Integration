//! Rust backend for Square × UniFi Protect.
//!
//! The browser assets and SQLite layout intentionally remain compatible with
//! the legacy service. This lets an installation upgrade without re-entering
//! credentials or resetting local accounts.

pub mod clients;
pub mod config;
pub mod error;
pub mod models;
pub mod security;
pub mod store;
pub mod sync;
pub mod thumbnail;
pub mod tls;
pub mod web;

pub use config::Config;
pub use error::{AppError, AppResult};
pub use store::Store;
pub use web::{AppState, build_router};
