//! Функции вывода ключей (КР-1, P-GOST-KDF):
//! - HKDF-Стрибог-256 — точный код ТП §23.2.3 (исправление C-09);
//! - KDF_GOSTR3411_2012_256 — RFC 7836 §4.5 (KAT B.9);
//! - KDF_TREE_GOSTR3411_2012_256 — RFC 7836 §4.4 (KAT B.10).

use crate::hash::hmac_streebog256;

/// HKDF (RFC 5869) на HMAC-Стрибог-256 — реализация из ТП §23.2.3 (C-09).
pub fn hkdf_streebog256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let prk = hmac_streebog256(salt, ikm);

    let mut okm: Vec<u8> = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < out_len {
        let mut data: Vec<u8> = Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(counter);
        t = hmac_streebog256(&prk, &data).to_vec();
        okm.extend_from_slice(&t);
        counter = counter.checked_add(1).expect("переполнение HKDF-счётчика");
    }
    okm.truncate(out_len);
    okm
}

/// KDF_GOSTR3411_2012_256(K_in, label, seed) =
///   HMAC_256(K_in, 0x01 | label | 0x00 | seed | 0x01 | 0x00)   (RFC 7836 §4.5)
pub fn kdf_gostr3411_2012_256(k_in: &[u8], label: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(label.len() + seed.len() + 4);
    data.push(0x01);
    data.extend_from_slice(label);
    data.push(0x00);
    data.extend_from_slice(seed);
    data.push(0x01);
    data.push(0x00);
    hmac_streebog256(k_in, &data)
}

/// KDF_TREE_GOSTR3411_2012_256(K_in, label, seed, R) для L бит (RFC 7836 §4.4):
/// K(i) = HMAC(K_in, [i]_R | label | 0x00 | seed | [L]_b), i = 1..
/// [i]_R — R байт big-endian; [L]_b — минимальное big-endian представление L.
pub fn kdf_tree_gostr3411_2012_256(
    k_in: &[u8],
    label: &[u8],
    seed: &[u8],
    r: usize,
    out_bits: usize,
) -> Vec<u8> {
    assert!((1..=4).contains(&r), "R must be 1..=4");
    assert!(out_bits > 0 && out_bits <= 256 * ((1usize << (8 * r)) - 1));
    let l_bytes = be_minimal(out_bits as u64);
    let mut okm = Vec::with_capacity(out_bits.div_ceil(8));
    let mut i: u64 = 1;
    while okm.len() * 8 < out_bits {
        let mut data = Vec::new();
        data.extend_from_slice(&be_fixed(i, r));
        data.extend_from_slice(label);
        data.push(0x00);
        data.extend_from_slice(seed);
        data.extend_from_slice(&l_bytes);
        okm.extend_from_slice(&hmac_streebog256(k_in, &data));
        i += 1;
    }
    okm.truncate(out_bits.div_ceil(8));
    okm
}

fn be_minimal(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let start = b.iter().position(|x| *x != 0).unwrap_or(7);
    b[start..].to_vec()
}

fn be_fixed(v: u64, len: usize) -> Vec<u8> {
    let b = v.to_be_bytes();
    b[8 - len..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakura_common::hex;

    /// KAT RFC 7836 B.9: KDF_GOSTR3411_2012_256.
    #[test]
    fn kdf_b9() {
        let k_in: Vec<u8> = (0x00u8..0x20).collect();
        let label = hex::decode("26bdb878").unwrap();
        let seed = hex::decode("af21434145656378").unwrap();
        let out = kdf_gostr3411_2012_256(&k_in, &label, &seed);
        assert_eq!(
            hex::encode(&out),
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
        );
    }

    /// KAT RFC 7836 B.10: KDF_TREE, L=512, R=1 → K1, K2.
    #[test]
    fn kdf_tree_b10() {
        let k_in: Vec<u8> = (0x00u8..0x20).collect();
        let label = hex::decode("26bdb878").unwrap();
        let seed = hex::decode("af21434145656378").unwrap();
        let out = kdf_tree_gostr3411_2012_256(&k_in, &label, &seed, 1, 512);
        assert_eq!(
            hex::encode(&out[..32]),
            "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b"
        );
        assert_eq!(
            hex::encode(&out[32..]),
            "074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
        );
    }

    /// HKDF: RFC 5869-семантика (свойства), детерминизм, разделение доменов.
    #[test]
    fn hkdf_properties() {
        let ikm = b"input keying material";
        let a = hkdf_streebog256(ikm, b"salt", b"info-A", 64);
        let b = hkdf_streebog256(ikm, b"salt", b"info-A", 64);
        let c = hkdf_streebog256(ikm, b"salt", b"info-B", 64);
        assert_eq!(a, b, "детерминизм");
        assert_ne!(a, c, "domain separation по info");
        assert_eq!(a.len(), 64);
        // префикс-свойство: 32 байта — префикс 64-байтового вывода
        let short = hkdf_streebog256(ikm, b"salt", b"info-A", 32);
        assert_eq!(&a[..32], &short[..]);
    }
}
