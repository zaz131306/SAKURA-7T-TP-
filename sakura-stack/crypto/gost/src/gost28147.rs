//! ГОСТ 28147-89 (таблица замен id-tc26-gost-28147-param-Z, RFC 7836 App. C):
//! - ECB («простая замена», 32 раунда) — для key wrap RFC 7836 §4.6;
//! - IMIT MAC (16 раундов, 4-байтовый результат);
//! - wrap/unwrap ключей по RFC 7836 §4.6 (P-GOST-WRAP, профиль КР-1).
//!
//! Байтовая конвенция (профиль КР-1, сверена с KAT RFC 7836 B.11):
//! ключевые слова X1..X8 — little-endian u32 из последовательных 4 байт;
//! блок данных: v0 = LE(байты 4..8), v1 = LE(байты 0..4);
//! выход: LE(v0') || LE(v1'). (Соответствует CryptoPro-представлению
//! «на проводе» и байт-в-байт воспроизводит вектор B.11.)
//!
//! KAT: RFC 7836 Appendix B.11 — KEK_e, CEK_ENC и CEK_MAC.

use crate::hash::constant_time_eq;
use crate::kdf::kdf_gostr3411_2012_256;

/// Таблицы замен param-Z (RFC 7836 App. C = id-tc26-gost-28147-param-Z =
/// таблица ГОСТ Р 34.12-2015): PI[i][x].
const PI: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

/// Фиксированная метка KEK для wrap (RFC 7836 §4.6): 0x26|0xBD|0xB8|0x78.
pub const WRAP_LABEL: [u8; 4] = [0x26, 0xBD, 0xB8, 0x78];

fn g(x: u32, k: u32) -> u32 {
    let t = x.wrapping_add(k);
    let mut s = 0u32;
    for i in 0..8 {
        let nib = ((t >> (4 * i)) & 0xf) as usize;
        s |= (PI[i][nib] as u32) << (4 * i);
    }
    s.rotate_left(11)
}

fn subkeys(key32: &[u8; 32]) -> [u32; 8] {
    let mut x = [0u32; 8];
    for i in 0..8 {
        x[i] = u32::from_le_bytes(key32[i * 4..i * 4 + 4].try_into().unwrap());
    }
    x
}

fn block_words(wire: &[u8; 8]) -> (u32, u32) {
    let v0 = u32::from_le_bytes(wire[4..8].try_into().unwrap());
    let v1 = u32::from_le_bytes(wire[0..4].try_into().unwrap());
    (v0, v1)
}

fn words_block(v0: u32, v1: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&v0.to_le_bytes());
    out[4..8].copy_from_slice(&v1.to_le_bytes());
    out
}

#[inline]
fn round(v: &mut (u32, u32), k: u32) {
    *v = (v.1, v.0 ^ g(v.1, k));
}

/// Шифрование блока (32 раунда, «простая замена»: X1..X8 ×3, затем X8..X1).
pub fn ecb_encrypt_block(key32: &[u8; 32], block: &[u8; 8]) -> [u8; 8] {
    let x = subkeys(key32);
    let mut v = block_words(block);
    for _ in 0..3 {
        for i in 0..8 {
            round(&mut v, x[i]);
        }
    }
    for i in (0..8).rev() {
        round(&mut v, x[i]);
    }
    words_block(v.0, v.1)
}

/// Расшифрование блока (обратное расписание: X1..X8, затем X8..X1 ×3).
pub fn ecb_decrypt_block(key32: &[u8; 32], block: &[u8; 8]) -> [u8; 8] {
    let x = subkeys(key32);
    let mut v = block_words(block);
    for i in 0..8 {
        round(&mut v, x[i]);
    }
    for _ in 0..3 {
        for i in (0..8).rev() {
            round(&mut v, x[i]);
        }
    }
    words_block(v.0, v.1)
}

/// ECB-шифрование данных (длина кратна 8).
pub fn ecb_encrypt(key32: &[u8; 32], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 8 == 0, "ECB: данные кратны 8 байтам");
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        out.extend_from_slice(&ecb_encrypt_block(key32, &b));
    }
    out
}

pub fn ecb_decrypt(key32: &[u8; 32], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 8 == 0);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        out.extend_from_slice(&ecb_decrypt_block(key32, &b));
    }
    out
}

/// 16-раундовое преобразование IMIT (X1..X8 дважды, без финального обмена).
fn enc16(v: &mut (u32, u32), x: &[u32; 8]) {
    for i in 0..16 {
        round(v, x[i % 8]);
    }
}

/// IMIT MAC (ГОСТ 28147-89): 16 раундов, цепочка от IV, результат — 4 байта.
/// Частичный последний блок дополняется нулями.
pub fn imit_mac(key32: &[u8; 32], iv8: &[u8; 8], data: &[u8]) -> [u8; 4] {
    let x = subkeys(key32);
    let mut cm = block_words(iv8);
    let mut buf = data.to_vec();
    if buf.is_empty() || buf.len() % 8 != 0 {
        let pad = (8 - buf.len() % 8) % 8;
        buf.extend(std::iter::repeat(0u8).take(pad));
    }
    for chunk in buf.chunks(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        let s = block_words(&b);
        let mut v = (cm.0 ^ s.0, cm.1 ^ s.1);
        enc16(&mut v, &x);
        cm = v;
    }
    // MAC = младшие 32 бита CM в проводной конвенции КР-1 (KAT RFC 7836 B.11)
    cm.1.to_le_bytes()
}

/// Обёртка ключа по RFC 7836 §4.6:
/// wrapped = seed(8..16) || CEK_ENC || CEK_MAC,
/// KEK_e = KDF_GOSTR3411_2012_256(K_e, label, seed), IV MAC = seed[0..8].
#[derive(Debug)]
pub enum WrapError {
    BadSeedLen,
    BadKeyLen,
    MacMismatch,
}

pub fn wrap_key(ke_key: &[u8; 32], key_material: &[u8], seed: &[u8]) -> Result<Vec<u8>, WrapError> {
    if !(8..=16).contains(&seed.len()) {
        return Err(WrapError::BadSeedLen);
    }
    if key_material.is_empty() || key_material.len() % 8 != 0 {
        return Err(WrapError::BadKeyLen);
    }
    let kek_e = kdf_gostr3411_2012_256(ke_key, &WRAP_LABEL, seed);
    let cek_enc = ecb_encrypt(&kek_e, key_material);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&seed[..8]);
    let cek_mac = imit_mac(&kek_e, &iv, key_material);
    let mut out = Vec::with_capacity(seed.len() + cek_enc.len() + 4);
    out.extend_from_slice(seed);
    out.extend_from_slice(&cek_enc);
    out.extend_from_slice(&cek_mac);
    Ok(out)
}

pub fn unwrap_key(ke_key: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
    // Профиль КР-1: seed фиксирован 8 байт.
    const SEED_LEN: usize = 8;
    if wrapped.len() < SEED_LEN + 12 {
        return Err(WrapError::BadSeedLen);
    }
    let seed = &wrapped[..SEED_LEN];
    let mac = &wrapped[wrapped.len() - 4..];
    let cek_enc = &wrapped[SEED_LEN..wrapped.len() - 4];
    if cek_enc.is_empty() || cek_enc.len() % 8 != 0 {
        return Err(WrapError::BadKeyLen);
    }
    let kek_e = kdf_gostr3411_2012_256(ke_key, &WRAP_LABEL, seed);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(seed);
    let key_material = ecb_decrypt(&kek_e, cek_enc);
    let calc = imit_mac(&kek_e, &iv, &key_material);
    if !constant_time_eq(&calc, mac) {
        return Err(WrapError::MacMismatch);
    }
    Ok(key_material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakura_common::hex;

    /// KAT RFC 7836 B.11: wrap-вектор (KEK_e, CEK_ENC, CEK_MAC).
    #[test]
    fn rfc7836_b11_kat() {
        let ke: [u8; 32] = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
        let k = hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let seed = hex::decode("af21434145656378").unwrap();

        let kek_e = kdf_gostr3411_2012_256(&ke, &WRAP_LABEL, &seed);
        assert_eq!(
            hex::encode(&kek_e),
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
        );

        let enc = ecb_encrypt(&kek_e, &k);
        assert_eq!(
            hex::encode(&enc),
            "d15547f8ee85121bc87d4b1027d26027ecc071bba6e72f3fec6f620f56834c5a"
        );

        let mut iv = [0u8; 8];
        iv.copy_from_slice(&seed);
        let mac = imit_mac(&kek_e, &iv, &k);
        assert_eq!(hex::encode(&mac), "be33f052");

        let wrapped = wrap_key(&ke, &k, &seed).unwrap();
        assert_eq!(wrapped.len(), 8 + 32 + 4);
        assert_eq!(&wrapped[8..40], &enc[..]);
        assert_eq!(&wrapped[40..], &mac[..]);
        let unwrapped = unwrap_key(&ke, &wrapped).unwrap();
        assert_eq!(unwrapped, k);

        let mut bad = wrapped.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(matches!(unwrap_key(&ke, &bad), Err(WrapError::MacMismatch)));
    }

    #[test]
    fn ecb_roundtrip_random() {
        let mut key = [0u8; 32];
        sakura_common::rand::fill(&mut key);
        let mut data = vec![0u8; 64];
        sakura_common::rand::fill(&mut data);
        let enc = ecb_encrypt(&key, &data);
        let dec = ecb_decrypt(&key, &enc);
        assert_eq!(dec, data);
        assert_ne!(enc, data);
    }

    /// Вектор ГОСТ 34.12-2015 (Magma = 28147-89 с таблицей Z) из документации
    /// эталонной реализации: key FFEEDDCC…/F0F1…, pt FEDCBA9876543210 →
    /// ct 4EE901E5C2D8CA3D. Проверяет раундовую функцию в BE-представлении.
    #[test]
    fn gost3412_a2_round_function() {
        let key = hex::decode("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let pt = hex::decode("fedcba9876543210").unwrap();
        let want = "4ee901e5c2d8ca3d";
        // внутреннее представление: X[i] = BE, v0 = BE(pt[0..4]), v1 = BE(pt[4..8]),
        // out = BE(v1f) || BE(v0f) — как в эталонной реализации RustCrypto magma.
        let mut x = [0u32; 8];
        for i in 0..8 {
            x[i] = u32::from_be_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut v = (
            u32::from_be_bytes(pt[0..4].try_into().unwrap()),
            u32::from_be_bytes(pt[4..8].try_into().unwrap()),
        );
        for _ in 0..3 {
            for i in 0..8 {
                round(&mut v, x[i]);
            }
        }
        for i in (0..8).rev() {
            round(&mut v, x[i]);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&v.1.to_be_bytes());
        out.extend_from_slice(&v.0.to_be_bytes());
        assert_eq!(hex::encode(&out), want);
    }
}
