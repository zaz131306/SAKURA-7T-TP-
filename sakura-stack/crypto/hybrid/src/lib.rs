//! sakura-hybrid — гибридный криптопрофиль КР-1 (§23.3):
//!
//! - Подпись: `concat(GOST_sig(64), ML-DSA-65_sig(3309))` = 3373 байта;
//!   проверка требует обе подписи valid (§23.3.3, §27.2 split_hybrid_signature).
//! - KEM-combiner: VKO ГОСТ Р 34.10-2012 + ML-KEM-1024 → HKDF-Стрибог-256
//!   (точный код ТП §23.3.2).
//! - AEAD: Кузнечик-MGM (P-GOST-MGM, BC-21): тег 128 бит, IV baseline 128 бит,
//!   AAD обязателен, IV уникален на ключ (no IV reuse).
//!
//! Решение КР-1 по BC-21 (IV 128 бит при 96-битном счётчике MGM):
//! nonce MGM = IV[0..12]; IV[12..16] включается в начало AAD — полный
//! 128-битный IV аутентифицируется и связывается с каналом.
#![forbid(unsafe_code)]

pub mod aead_mgm;
pub mod sign;

pub use aead_mgm::{mgm_decrypt, mgm_encrypt, AeadError, MGM_IV_LEN, MGM_KEY_LEN, MGM_TAG_LEN};
pub use sign::{
    hybrid_kem_combine, hybrid_sign, hybrid_sign_deterministic, hybrid_verify,
    kem_establish_decapsulate, kem_establish_encapsulate, split_hybrid_signature,
    HybridKeyPair, HybridPublicKey, HybridSignError, ALG_GOST_PLUS_MLDSA65, GOST_PK_LEN,
    GOST_SIG_LEN, HYBRID_PK_LEN, HYBRID_SIG_LEN, MLDSA_PK_LEN, MLDSA_SIG_LEN, MLKEM_EK_LEN,
};
