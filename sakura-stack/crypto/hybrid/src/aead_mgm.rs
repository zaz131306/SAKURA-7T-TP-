//! Кузнечик-MGM (ГОСТ Р 34.13-2015, P-GOST-MGM) — AEAD профиля КР-1 (BC-21):
//! - тег 128 бит;
//! - IV baseline 128 бит: nonce MGM = полный 16-байтовый IV со сброшенным
//!   старшим битом (требование ГОСТ Р 34.13-2015 §5.5: 127 значащих бит);
//! - AAD обязателен как параметр (связывает заголовок кадра/контекст);
//! - запрет повторного использования IV на ключ — IV формируется счётчиком
//!   сессии NPP (seq + направление), no IV reuse (BC-21).

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, NewAead};
use kuznyechik::Kuznyechik;

pub const MGM_KEY_LEN: usize = 32;
pub const MGM_IV_LEN: usize = 16; // BC-21 baseline
pub const MGM_TAG_LEN: usize = 16; // 128 бит

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadError {
    BadKeyLen,
    BadIvLen,
    /// Старший бит IV установлен — недопустимо для MGM (ГОСТ Р 34.13-2015).
    IvMsbSet,
    AuthFailed,
}

type KuzMgm = mgm::Mgm<Kuznyechik>;

/// Шифрование: возвращает ciphertext || tag(16).
pub fn mgm_encrypt(
    key: &[u8; MGM_KEY_LEN],
    iv: &[u8; MGM_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if iv[0] >> 7 != 0 {
        return Err(AeadError::IvMsbSet);
    }
    let c = KuzMgm::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(iv);
    let mut data = plaintext.to_vec();
    let tag = c
        .encrypt_in_place_detached(nonce, aad, &mut data)
        .map_err(|_| AeadError::AuthFailed)?;
    data.extend_from_slice(&tag);
    Ok(data)
}

/// Расшифрование и проверка тега: вход — ciphertext || tag(16).
pub fn mgm_decrypt(
    key: &[u8; MGM_KEY_LEN],
    iv: &[u8; MGM_IV_LEN],
    aad: &[u8],
    ct_with_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if iv[0] >> 7 != 0 {
        return Err(AeadError::IvMsbSet);
    }
    if ct_with_tag.len() < MGM_TAG_LEN {
        return Err(AeadError::AuthFailed);
    }
    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - MGM_TAG_LEN);
    let c = KuzMgm::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(iv);
    let mut data = ct.to_vec();
    c.decrypt_in_place_detached(nonce, aad, &mut data, GenericArray::from_slice(tag))
        .map_err(|_| AeadError::AuthFailed)?;
    Ok(data)
}

/// Проверка формата ключа/IV для slice-based вызовов (BC-18).
pub fn mgm_check_sizes(key: &[u8], iv: &[u8]) -> Result<(), AeadError> {
    if key.len() != MGM_KEY_LEN {
        return Err(AeadError::BadKeyLen);
    }
    if iv.len() != MGM_IV_LEN {
        return Err(AeadError::BadIvLen);
    }
    if iv.first().map(|b| b >> 7 != 0).unwrap_or(true) {
        return Err(AeadError::IvMsbSet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_iv() -> ([u8; 32], [u8; 16]) {
        let mut k = [0u8; 32];
        let mut iv = [0u8; 16];
        k.copy_from_slice(b"0123456789abcdef0123456789abcdef");
        iv.copy_from_slice(b"\x00unique-iv-00001");
        (k, iv)
    }

    #[test]
    fn mgm_roundtrip_and_tamper() {
        let (k, iv) = key_iv();
        let aad = b"frame-header-bytes";
        let pt = b"control command payload \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5";
        let ct = mgm_encrypt(&k, &iv, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + MGM_TAG_LEN);
        let dec = mgm_decrypt(&k, &iv, aad, &ct).unwrap();
        assert_eq!(dec, pt);
        // тамперинг ciphertext
        let mut bad = ct.clone();
        bad[3] ^= 1;
        assert!(mgm_decrypt(&k, &iv, aad, &bad).is_err());
        // тамперинг AAD
        assert!(mgm_decrypt(&k, &iv, b"other-aad", &ct).is_err());
        // тамперинг IV
        let mut iv2 = iv;
        iv2[15] ^= 1;
        assert!(mgm_decrypt(&k, &iv2, aad, &ct).is_err());
        // другой ключ
        let mut k2 = k;
        k2[0] ^= 1;
        assert!(mgm_decrypt(&k2, &iv, aad, &ct).is_err());
    }

    #[test]
    fn mgm_empty_payload() {
        let (k, iv) = key_iv();
        let ct = mgm_encrypt(&k, &iv, b"aad-only", b"").unwrap();
        assert_eq!(ct.len(), MGM_TAG_LEN);
        assert_eq!(mgm_decrypt(&k, &iv, b"aad-only", &ct).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn mgm_rejects_msb_iv() {
        let (k, mut iv) = key_iv();
        iv[0] = 0x80;
        assert_eq!(mgm_encrypt(&k, &iv, b"", b"x"), Err(AeadError::IvMsbSet));
        assert_eq!(mgm_decrypt(&k, &iv, b"", &[0u8; 16]), Err(AeadError::IvMsbSet));
        assert_eq!(mgm_check_sizes(&k, &iv), Err(AeadError::IvMsbSet));
    }
}
