//! Гибридная подпись и KEM (КР-1 §23.3).

use sakura_gost::gost3410;
use sakura_gost::hash::streebog256;
use sakura_gost::kdf::hkdf_streebog256;
use zeroize::Zeroize;

/// Идентификатор гибридного алгоритма подписи (профиль КР-1):
/// ГОСТ Р 34.10-2012 (256, paramSetA) + ML-DSA-65.
pub const ALG_GOST_PLUS_MLDSA65: u8 = 0x10;

pub const GOST_SIG_LEN: usize = 64;
pub const MLDSA_SIG_LEN: usize = sakura_pq::MLDSA65_SIG_LEN; // 3309
pub const HYBRID_SIG_LEN: usize = GOST_SIG_LEN + MLDSA_SIG_LEN; // 3373 (§13.7)
pub const GOST_PK_LEN: usize = 64;
pub const MLDSA_PK_LEN: usize = sakura_pq::MLDSA65_PK_LEN; // 1952
pub const HYBRID_PK_LEN: usize = GOST_PK_LEN + MLDSA_PK_LEN; // 2016
pub const MLKEM_EK_LEN: usize = sakura_pq::MLKEM1024_EK_LEN; // 1568

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HybridSignError {
    Gost(gost3410::GostSignError),
    Pq(sakura_pq::PqError),
    UnsupportedAlgorithm,
    SignatureTooShort,
}

/// Публичный гибридный ключ: gost(64) || mldsa(1952) || mlkem_ek(1568).
/// (ML-KEM encapsulation key включён — используется установлением сессий NPP.)
#[derive(Clone, Debug)]
pub struct HybridPublicKey {
    pub gost: [u8; GOST_PK_LEN],
    pub mldsa: Vec<u8>,
    pub mlkem_ek: Vec<u8>,
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HYBRID_PK_LEN + MLKEM_EK_LEN);
        v.extend_from_slice(&self.gost);
        v.extend_from_slice(&self.mldsa);
        v.extend_from_slice(&self.mlkem_ek);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != HYBRID_PK_LEN + MLKEM_EK_LEN {
            return None;
        }
        Some(HybridPublicKey {
            gost: b[..64].try_into().unwrap(),
            mldsa: b[64..64 + MLDSA_PK_LEN].to_vec(),
            mlkem_ek: b[64 + MLDSA_PK_LEN..].to_vec(),
        })
    }
}

/// Секретный гибридный ключ (хранится только внутри HSM; §13.6 no key export).
#[derive(Clone)]
pub struct HybridKeyPair {
    pub gost_priv: [u8; 32],
    pub mldsa_sk: Vec<u8>,
    pub mlkem_dk: Vec<u8>,
    pub public: HybridPublicKey,
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        self.gost_priv.zeroize();
        self.mldsa_sk.zeroize();
        self.mlkem_dk.zeroize();
    }
}

impl HybridKeyPair {
    /// Генерация внутри «HSM» (в SoftHsm — эквивалент generate_key).
    pub fn generate() -> Result<Self, HybridSignError> {
        let mut gost_priv = [0u8; 32];
        loop {
            sakura_common::rand::fill(&mut gost_priv);
            gost_priv[0] &= 0x3F; // приведение к диапазону (0, q)
            if !gost_priv.iter().all(|b| *b == 0) {
                break;
            }
        }
        let gost = gost3410::public_from_private(&gost_priv).map_err(HybridSignError::Gost)?;
        let (mldsa_pk, mldsa_sk) = sakura_pq::mldsa65_keygen_os().map_err(HybridSignError::Pq)?;
        let (mlkem_dk, mlkem_ek) = sakura_pq::mlkem1024_keygen_os().map_err(HybridSignError::Pq)?;
        Ok(HybridKeyPair {
            gost_priv,
            mldsa_sk: mldsa_sk.to_vec(),
            mlkem_dk,
            public: HybridPublicKey { gost, mldsa: mldsa_pk.to_vec(), mlkem_ek },
        })
    }
}

/// Гибридная подпись сообщения (§23.3.3):
/// GOST-часть подписывает Стрибог-256(msg), ML-DSA-часть — msg целиком.
pub fn hybrid_sign(kp: &HybridKeyPair, msg: &[u8]) -> Result<Vec<u8>, HybridSignError> {
    let digest = streebog256(msg);
    let gost_sig = gost3410::sign(&kp.gost_priv, &digest).map_err(HybridSignError::Gost)?;
    let pq_sig = sakura_pq::mldsa65_sign(&kp.mldsa_sk, msg, b"").map_err(HybridSignError::Pq)?;
    let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
    out.extend_from_slice(&gost_sig);
    out.extend_from_slice(&pq_sig);
    Ok(out)
}

/// Детерминированная гибридная подпись с фиксированным ГОСТ-k (для KAT).
pub fn hybrid_sign_deterministic(
    kp: &HybridKeyPair,
    msg: &[u8],
    gost_k: &[u8; 32],
) -> Result<Vec<u8>, HybridSignError> {
    let digest = streebog256(msg);
    let gost_sig =
        gost3410::sign_deterministic(&kp.gost_priv, &digest, gost_k).map_err(HybridSignError::Gost)?;
    let pq_sig = sakura_pq::mldsa65_sign(&kp.mldsa_sk, msg, b"").map_err(HybridSignError::Pq)?;
    let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
    out.extend_from_slice(&gost_sig);
    out.extend_from_slice(&pq_sig);
    Ok(out)
}

/// Разбиение гибридной подписи (§27.2, C-02): GOST 64 Б || ML-DSA-65 3309 Б.
pub fn split_hybrid_signature(sig: &[u8], alg: u8) -> Result<(&[u8], &[u8]), HybridSignError> {
    match alg {
        ALG_GOST_PLUS_MLDSA65 => {
            if sig.len() < GOST_SIG_LEN {
                return Err(HybridSignError::SignatureTooShort);
            }
            Ok((&sig[..GOST_SIG_LEN], &sig[GOST_SIG_LEN..]))
        }
        _ => Err(HybridSignError::UnsupportedAlgorithm),
    }
}

/// Проверка: обе подписи должны быть валидны (§23.3.3).
pub fn hybrid_verify(pk: &HybridPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let (gost_sig, pq_sig) = match split_hybrid_signature(sig, ALG_GOST_PLUS_MLDSA65) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if gost_sig.len() != GOST_SIG_LEN || pq_sig.len() != MLDSA_SIG_LEN {
        return false;
    }
    let digest = streebog256(msg);
    let mut gs = [0u8; GOST_SIG_LEN];
    gs.copy_from_slice(gost_sig);
    let gost_ok = gost3410::verify(&pk.gost, &digest, &gs);
    let pq_ok = sakura_pq::mldsa65_verify(&pk.mldsa, msg, b"", pq_sig);
    gost_ok && pq_ok
}

/// KEM-combiner — точный код ТП §23.3.2.
pub fn hybrid_kem_combine(
    ss_gost: &[u8],
    ss_pq: &[u8],
    context_salt: &[u8],
    protocol: &str,
    epoch: u64,
) -> Vec<u8> {
    let mut ikm = Vec::new();
    ikm.extend_from_slice(ss_gost);
    ikm.extend_from_slice(ss_pq);

    let mut info = Vec::new();
    info.extend_from_slice(b"HYBRID-KEM");
    info.extend_from_slice(protocol.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());

    hkdf_streebog256(&ikm, context_salt, &info, 32)
}

/// Сторона-инициатор установления сессии (§13.3 SESSION_ESTABLISH):
/// эфемерная ГОСТ-пара + инкапсуляция ML-KEM под статический ek собеседника.
/// Возвращает (ukm, gost_eph_pub, mlkem_ct, session_key).
pub fn kem_establish_encapsulate(
    peer: &HybridPublicKey,
    transcript_salt: &[u8],
    protocol: &str,
    epoch: u64,
) -> Result<(u64, [u8; 64], Vec<u8>, [u8; 32]), HybridSignError> {
    let mut eph_priv = [0u8; 32];
    loop {
        sakura_common::rand::fill(&mut eph_priv);
        eph_priv[0] &= 0x3F;
        if !eph_priv.iter().all(|b| *b == 0) {
            break;
        }
    }
    let eph_pub = gost3410::public_from_private(&eph_priv).map_err(HybridSignError::Gost)?;
    let mut ukm_b = [0u8; 8];
    sakura_common::rand::fill(&mut ukm_b);
    let ukm = u64::from_le_bytes(ukm_b) | 1; // UKM ∈ [1, 2⁶⁴)

    let ss_gost =
        gost3410::vko_kek_256(&eph_priv, &peer.gost, ukm).map_err(HybridSignError::Gost)?;
    let (ct, ss_pq) = sakura_pq::mlkem1024_encapsulate(&peer.mlkem_ek).map_err(HybridSignError::Pq)?;
    let key_bytes = hybrid_kem_combine(&ss_gost, &ss_pq, transcript_salt, protocol, epoch);
    eph_priv.zeroize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok((ukm, eph_pub, ct, key))
}

/// Сторона-ответчик: статический ГОСТ-ключ + декапсуляция ML-KEM.
pub fn kem_establish_decapsulate(
    own: &HybridKeyPair,
    peer_eph_pub: &[u8; 64],
    ukm: u64,
    mlkem_ct: &[u8],
    transcript_salt: &[u8],
    protocol: &str,
    epoch: u64,
) -> Result<[u8; 32], HybridSignError> {
    let ss_gost =
        gost3410::vko_kek_256(&own.gost_priv, peer_eph_pub, ukm).map_err(HybridSignError::Gost)?;
    let ss_pq =
        sakura_pq::mlkem1024_decapsulate(&own.mlkem_dk, mlkem_ct).map_err(HybridSignError::Pq)?;
    let key_bytes = hybrid_kem_combine(&ss_gost, &ss_pq, transcript_salt, protocol, epoch);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let kp = HybridKeyPair::generate().unwrap();
        let msg = b"SubmitCommand payload #7";
        let sig = hybrid_sign(&kp, msg).unwrap();
        assert_eq!(sig.len(), HYBRID_SIG_LEN, "3373 байта (§13.7)");
        assert!(hybrid_verify(&kp.public, msg, &sig));
        // тамперинг любой половины ломает проверку
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!hybrid_verify(&kp.public, msg, &bad));
        let mut bad2 = sig.clone();
        bad2[GOST_SIG_LEN + 5] ^= 1;
        assert!(!hybrid_verify(&kp.public, msg, &bad2));
    }

    #[test]
    fn split_matches_spec_27_2() {
        let kp = HybridKeyPair::generate().unwrap();
        let sig = hybrid_sign(&kp, b"m").unwrap();
        let (g, p) = split_hybrid_signature(&sig, ALG_GOST_PLUS_MLDSA65).unwrap();
        assert_eq!(g.len(), 64);
        assert_eq!(p.len(), 3309);
        // неизвестный алгоритм → UnsupportedAlgorithm
        assert!(matches!(
            split_hybrid_signature(&sig, 0x7F),
            Err(HybridSignError::UnsupportedAlgorithm)
        ));
        // короткая подпись → SignatureTooShort
        assert!(matches!(
            split_hybrid_signature(&sig[..10], ALG_GOST_PLUS_MLDSA65),
            Err(HybridSignError::SignatureTooShort)
        ));
    }

    #[test]
    fn pk_serialization_roundtrip() {
        let kp = HybridKeyPair::generate().unwrap();
        let b = kp.public.to_bytes();
        let pk2 = HybridPublicKey::from_bytes(&b).unwrap();
        assert_eq!(pk2.gost, kp.public.gost);
        assert_eq!(pk2.mldsa, kp.public.mldsa);
        assert_eq!(pk2.mlkem_ek, kp.public.mlkem_ek);
        assert!(HybridPublicKey::from_bytes(&b[..100]).is_none());
    }

    /// Кросс-проверка: ключ инициатора и ответчика совпадают (symmetry VKO +
    /// ML-KEM), transcript salt связывает ключ с сессией (channel binding,
    /// §13.17).
    #[test]
    fn session_key_establishment() {
        let responder = HybridKeyPair::generate().unwrap();
        let salt = streebog256(b"session-transcript||hello||challenge");
        let (ukm, eph_pub, ct, key_i) =
            kem_establish_encapsulate(&responder.public, &salt, "NPP-v2.3", 1).unwrap();
        let key_r = kem_establish_decapsulate(
            &responder,
            &eph_pub,
            ukm,
            &ct,
            &salt,
            "NPP-v2.3",
            1,
        )
        .unwrap();
        assert_eq!(key_i, key_r);
        // другой transcript → другой ключ
        let salt2 = streebog256(b"other-transcript");
        let key_r2 = kem_establish_decapsulate(
            &responder,
            &eph_pub,
            ukm,
            &ct,
            &salt2,
            "NPP-v2.3",
            1,
        )
        .unwrap();
        assert_ne!(key_i, key_r2);
    }

    #[test]
    fn combiner_matches_spec_code() {
        // детерминированная проверка точного кода §23.3.2
        let ss = hybrid_kem_combine(&[1u8; 32], &[2u8; 32], &[3u8; 16], "PROTO", 42);
        let ss2 = hybrid_kem_combine(&[1u8; 32], &[2u8; 32], &[3u8; 16], "PROTO", 42);
        assert_eq!(ss, ss2);
        assert_eq!(ss.len(), 32);
        let ss3 = hybrid_kem_combine(&[1u8; 32], &[2u8; 32], &[3u8; 16], "PROTO", 43);
        assert_ne!(ss, ss3);
    }
}
