//! sakura-gost — криптографическое ядро ГОСТ (КР-1, §23.2):
//! - [`gost3410`] — ГОСТ Р 34.10-2012 (256 бит, paramSetA) + VKO (RFC 7836 §4.3.1);
//! - [`hash`] — Стрибог-256/512 (ГОСТ Р 34.11-2012), HMAC, constant-time compare;
//! - [`kdf`] — HKDF-Стрибог-256 (ТП §23.2.3, C-09), KDF/KDF_TREE (RFC 7836 §4.4–4.5);
//! - [`gost28147`] — ГОСТ 28147-89 param-Z: ECB, IMIT, key wrap (RFC 7836 §4.6);
//! - [`curve`], [`u256`] — математика (Монтгомери, якобиановы точки).
//!
//! Профили КР-1 (§23.2.2): P-GOST-SIGN, P-GOST-HASH-256/512, P-GOST-KDF,
//! P-GOST-HMAC, P-GOST-WRAP, P-GOST-ECDH (VKO). P-GOST-CIPHER/P-GOST-MGM —
//! в crate sakura-hybrid (Кузнечик + MGM, BC-21).
#![forbid(unsafe_code)]

pub mod curve;
pub mod gost28147;
pub mod gost3410;
pub mod hash;
pub mod kdf;
pub mod u256;

/// Константы кривой и KAT-векторы (автоген: tools/codegen/gen_kats.py).
#[allow(dead_code)]
pub mod kat;

// Идентификаторы алгоритмов (профиль КР-1 / §27.2 ТП).
/// Подпись: ГОСТ Р 34.10-2012 (256) + ML-DSA-65 (гибрид, 3373 байта).
pub const ALG_GOST_PLUS_MLDSA65: u8 = 0x10;
/// Хэш: Стрибог-256.
pub const ALG_STREEBOG_256: u8 = 0x20;
/// Хэш: Стрибог-512.
pub const ALG_STREEBOG_512: u8 = 0x21;

pub use gost3410::{public_from_private, sign, sign_deterministic, verify, verify_checked, vko_kek_256, GostSignError};
