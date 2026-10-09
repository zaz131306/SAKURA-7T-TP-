//! sakura-pq — постквантовый слой (КР-1, §23.3):
//! - ML-DSA-65 (FIPS 204) — подпись гибридного профиля (§23.3.3);
//! - ML-KEM-1024 (FIPS 203) — KEM гибридного профиля (§23.3.2, ≥192 бит PQ).
//!
//! Обёртки байт-ориентированы (HSM-agent slice-based API, BC-18).
//! Реализации — открытые audited crates (fips204, ml-kem), interim baseline
//! по §23.3.1 до утверждения национального PQ-профиля.
#![forbid(unsafe_code)]

use fips204::ml_dsa_65::{KG, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params};
use rand_core::{CryptoRng, RngCore};

/// Размеры ML-DSA-65 (FIPS 204).
pub const MLDSA65_PK_LEN: usize = PK_LEN;
pub const MLDSA65_SK_LEN: usize = SK_LEN;
pub const MLDSA65_SIG_LEN: usize = SIG_LEN;
/// Размеры ML-KEM-1024 (FIPS 203).
pub const MLKEM1024_EK_LEN: usize = 1568;
pub const MLKEM1024_DK_LEN: usize = 3168;
pub const MLKEM1024_CT_LEN: usize = 1568;
pub const MLKEM1024_SS_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqError {
    InvalidKeySize,
    InvalidSignatureSize,
    InvalidCiphertextSize,
    KeygenFailed,
    SignFailed,
    Malformed,
}

// ---------------- OS RNG адаптер (rand_core 0.6) ----------------

/// Адаптер ОС-энтропии к rand_core 0.6 (getrandom-бэккенд).
pub struct OsRngAdapter;

impl RngCore for OsRngAdapter {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        sakura_common::rand::fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for OsRngAdapter {}

// ---------------- ML-DSA-65 ----------------

/// Генерация ключевой пары ML-DSA-65 (в production — внутри HSM).
pub fn mldsa65_keygen_os() -> Result<([u8; MLDSA65_PK_LEN], [u8; MLDSA65_SK_LEN]), PqError> {
    let mut rng = OsRngAdapter;
    let (pk, sk) = KG::try_keygen_with_rng(&mut rng).map_err(|_| PqError::KeygenFailed)?;
    Ok((pk.into_bytes(), sk.into_bytes()))
}

pub fn mldsa65_sign(sk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<[u8; MLDSA65_SIG_LEN], PqError> {
    if sk.len() != MLDSA65_SK_LEN {
        return Err(PqError::InvalidKeySize);
    }
    let mut skb = [0u8; MLDSA65_SK_LEN];
    skb.copy_from_slice(sk);
    let sk = PrivateKey::try_from_bytes(skb).map_err(|_| PqError::Malformed)?;
    sk.try_sign(msg, ctx).map_err(|_| PqError::SignFailed)
}

pub fn mldsa65_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != MLDSA65_PK_LEN || sig.len() != MLDSA65_SIG_LEN {
        return false;
    }
    let mut pkb = [0u8; MLDSA65_PK_LEN];
    pkb.copy_from_slice(pk);
    let mut sb = [0u8; MLDSA65_SIG_LEN];
    sb.copy_from_slice(sig);
    match PublicKey::try_from_bytes(pkb) {
        Ok(pk) => pk.verify(msg, &sb, ctx),
        Err(_) => false,
    }
}

// ---------------- ML-KEM-1024 ----------------

type Dk = DecapsulationKey<MlKem1024Params>;
type Ek = EncapsulationKey<MlKem1024Params>;

pub fn mlkem1024_keygen_os() -> Result<(Vec<u8>, Vec<u8>), PqError> {
    let mut rng = OsRngAdapter;
    let (dk, ek) = MlKem1024::generate(&mut rng);
    Ok((dk.as_bytes().to_vec(), ek.as_bytes().to_vec()))
}

/// Инкапсуляция: возвращает (ciphertext, shared_secret).
pub fn mlkem1024_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), PqError> {
    if ek_bytes.len() != MLKEM1024_EK_LEN {
        return Err(PqError::InvalidKeySize);
    }
    let enc: Encoded<Ek> =
        Encoded::<Ek>::try_from(ek_bytes).map_err(|_| PqError::InvalidKeySize)?;
    let ek = Ek::from_bytes(&enc);
    let mut rng = OsRngAdapter;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| PqError::KeygenFailed)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    Ok((ct.to_vec(), out))
}

/// Декапсуляция: возвращает shared secret.
pub fn mlkem1024_decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32], PqError> {
    if dk_bytes.len() != MLKEM1024_DK_LEN {
        return Err(PqError::InvalidKeySize);
    }
    if ct_bytes.len() != MLKEM1024_CT_LEN {
        return Err(PqError::InvalidCiphertextSize);
    }
    let enc_dk: Encoded<Dk> =
        Encoded::<Dk>::try_from(dk_bytes).map_err(|_| PqError::InvalidKeySize)?;
    let dk = Dk::from_bytes(&enc_dk);
    let enc_ct: ml_kem::Ciphertext<MlKem1024> =
        ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes)
            .map_err(|_| PqError::InvalidCiphertextSize)?;
    let ss = dk.decapsulate(&enc_ct).map_err(|_| PqError::Malformed)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa65_roundtrip_and_sizes() {
        let (pk, sk) = mldsa65_keygen_os().unwrap();
        assert_eq!(pk.len(), 1952);
        assert_eq!(sk.len(), 4032);
        let msg = b"attestation report payload";
        let sig = mldsa65_sign(&sk, msg, b"").unwrap();
        assert_eq!(sig.len(), 3309, "ML-DSA-65 signature = 3309 B (§13.7)");
        assert!(mldsa65_verify(&pk, msg, b"", &sig));
        assert!(!mldsa65_verify(&pk, b"tampered", b"", &sig));
        let mut bad = sig;
        bad[100] ^= 1;
        assert!(!mldsa65_verify(&pk, msg, b"", &bad));
        let sig2 = mldsa65_sign(&sk, msg, b"ctx-A").unwrap();
        assert!(!mldsa65_verify(&pk, msg, b"ctx-B", &sig2));
    }

    #[test]
    fn mldsa65_rejects_bad_sizes() {
        assert!(matches!(mldsa65_sign(&[0u8; 10], b"x", b""), Err(PqError::InvalidKeySize)));
        assert!(!mldsa65_verify(&[0u8; 5], b"x", b"", &[0u8; 3309]));
    }

    #[test]
    fn mlkem1024_roundtrip() {
        let (dk, ek) = mlkem1024_keygen_os().unwrap();
        assert_eq!(ek.len(), MLKEM1024_EK_LEN);
        assert_eq!(dk.len(), MLKEM1024_DK_LEN);
        let (ct, ss1) = mlkem1024_encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), MLKEM1024_CT_LEN);
        let ss2 = mlkem1024_decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);
        // чужой ключ → другой секрет (неявный отказ FIPS 203), не совпадающий с ss1
        let (dk2, _ek2) = mlkem1024_keygen_os().unwrap();
        let ss3 = mlkem1024_decapsulate(&dk2, &ct).unwrap();
        assert_ne!(ss1, ss3);
    }
}
