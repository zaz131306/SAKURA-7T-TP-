//! Стрибог-256/512 (ГОСТ Р 34.11-2012) и HMAC (ГОСТ Р 34.11-2012 + RFC 2104).
//! Реализация хэша — сертифицируемая библиотека RustCrypto `streebog`
//! (КР-1: в production — сертифицированный ФСБ провайдер, здесь — открытая
//! реализация с KAT-контролем; §23.3.1 interim baseline).

use digest::Digest;
use hmac::{Hmac, Mac};
use streebog::{Streebog256, Streebog512};

pub type HmacStreebog256 = Hmac<Streebog256>;
pub type HmacStreebog512 = Hmac<Streebog512>;

pub fn streebog256(data: &[u8]) -> [u8; 32] {
    let mut h = Streebog256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn streebog512(data: &[u8]) -> [u8; 64] {
    let mut h = Streebog512::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

/// Incremental-обёртка (для measured boot / hash chain).
pub struct Hasher256(Streebog256);

impl Hasher256 {
    pub fn new() -> Self {
        Hasher256(Streebog256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        let out = self.0.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        r
    }
}

impl Default for Hasher256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hmac_streebog256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacStreebog256::new_from_slice(key).expect("HMAC принимает ключ любого размера");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn hmac_streebog512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacStreebog512::new_from_slice(key).expect("HMAC принимает ключ любого размера");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

/// Проверка MAC/подписи без утечки по времени (§23.2.2: constant-time compare).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT HMAC_GOSTR3411_2012_256 — RFC 7836 Appendix B.1.
    #[test]
    fn hmac256_rfc7836_b1() {
        let key: Vec<u8> = (0x00u8..0x20).collect();
        let t = sakura_common::hex::decode("0126bdb87800af214341456563780100").unwrap();
        let mac = hmac_streebog256(&key, &t);
        assert_eq!(
            sakura_common::hex::encode(&mac),
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
        );
    }

    /// KAT HMAC_GOSTR3411_2012_512 — RFC 7836 Appendix B.2.
    #[test]
    fn hmac512_rfc7836_b2() {
        let key: Vec<u8> = (0x00u8..0x20).collect();
        let t = sakura_common::hex::decode("0126bdb87800af214341456563780100").unwrap();
        let mac = hmac_streebog512(&key, &t);
        assert_eq!(
            sakura_common::hex::encode(&mac),
            "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77\
             3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
        );
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
