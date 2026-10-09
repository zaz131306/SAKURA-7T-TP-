//! sakura-common — общие примитивы платформы SAKURA STACK.
//!
//! - [`cbor`]  — детерминированный canonical CBOR (RFC 8949 §4.2.1, DM-1 §13.18.1);
//! - [`error`] — общие коды ошибок ICD-1 §13.8;
//! - [`uuid7`] — UUIDv7 (DM-1: node_id/cluster_id/plan_id/…);
//! - [`hex`], [`config`], [`time`] — вспомогательные утилиты.
#![forbid(unsafe_code)]

pub mod cbor;
pub mod config;
pub mod error;
pub mod hex;
pub mod rand;
pub mod time;
pub mod uuid7;

pub use cbor::Cbor;
pub use error::{ErrorCode, Severity};

/// Версия протокола платформы (ICD-1, NPP v2.3).
pub const PROTO_MAJOR: u8 = 2;
pub const PROTO_MINOR: u8 = 3;
/// Шифр изделия (ТП §1.1).
pub const PRODUCT_CIPHER: &str = "SAKURA-7T-TP";
pub const PRODUCT_NAME: &str = "Sakura Stack";
pub const SPEC_VERSION: &str = "2.3";
