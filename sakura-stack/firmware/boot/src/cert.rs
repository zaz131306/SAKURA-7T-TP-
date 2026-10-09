//! Сертификаты подписанта (профиль §23.5, упрощённый CBOR-формат платформы).
//!
//! Production: X.509 v3 с обязательными расширениями (§23.5) и OID из КР-2;
//! SIL-контур: внутренний canonical-CBOR сертификат (DM-1: детерминированная
//! сериализация), подписанный гибридной подписью эмитента. Маппинг полей
//! X.509 ↔ CBOR фиксируется в КР-2.

use sakura_common::cbor::Cbor;
use sakura_gost::hash::streebog256;
use sakura_hybrid::{hybrid_verify, HybridPublicKey};

/// Назначения ключей (keyUsage-профиль §23.5).
pub const USAGE_FIRMWARE_SIGN: u8 = 1;
pub const USAGE_DEVICE_IDENTITY: u8 = 2;
pub const USAGE_OPERATOR: u8 = 3;
pub const USAGE_MODEL_SIGN: u8 = 4;
pub const USAGE_UPDATE_SIGN: u8 = 5;
pub const USAGE_CA: u8 = 6;

#[derive(Clone, Debug)]
pub struct SignerCert {
    /// uuid7 субъекта.
    pub subject_id: [u8; 16],
    /// key_id эмитента (первые 16 Б Стрибог-256 от публичного ключа).
    pub signer_id: [u8; 16],
    pub public: HybridPublicKey,
    pub key_usage: u8,
    pub hw_rev_min: u16,
    pub not_before: u64,
    pub not_after: u64,
    /// Гибридная подпись эмитента по tbs().
    pub signature: Vec<u8>,
}

/// key_id публичного ключа: первые 16 байт Стрибог-256(pk.to_bytes()).
pub fn key_id_of_pub(pk: &HybridPublicKey) -> [u8; 16] {
    let h = streebog256(&pk.to_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

impl SignerCert {
    /// Данные, покрываемые подписью (canonical CBOR без поля signature).
    pub fn tbs(&self) -> Vec<u8> {
        Cbor::map(vec![
            (Cbor::text("subject_id"), Cbor::bytes(self.subject_id.to_vec())),
            (Cbor::text("signer_id"), Cbor::bytes(self.signer_id.to_vec())),
            (Cbor::text("public"), Cbor::bytes(self.public.to_bytes())),
            (Cbor::text("key_usage"), Cbor::UInt(self.key_usage as u64)),
            (Cbor::text("hw_rev_min"), Cbor::UInt(self.hw_rev_min as u64)),
            (Cbor::text("not_before"), Cbor::UInt(self.not_before)),
            (Cbor::text("not_after"), Cbor::UInt(self.not_after)),
        ])
        .to_vec()
    }

    /// subject_key_id (DM-1: ключ CRL, bstr(16)).
    pub fn subject_key_id(&self) -> [u8; 16] {
        key_id_of_pub(&self.public)
    }

    pub fn time_valid(&self, now: u64) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    /// Проверка, что сертификат выпущен владельцем issuer_pub
    /// (signer_id совпадает и подпись валидна) — §27.2 issued_by.
    pub fn issued_by(&self, issuer_pub: &HybridPublicKey) -> bool {
        if self.signer_id != key_id_of_pub(issuer_pub) {
            return false;
        }
        hybrid_verify(issuer_pub, &self.tbs(), &self.signature)
    }

    pub fn to_cbor(&self) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("subject_id"), Cbor::bytes(self.subject_id.to_vec())),
            (Cbor::text("signer_id"), Cbor::bytes(self.signer_id.to_vec())),
            (Cbor::text("public"), Cbor::bytes(self.public.to_bytes())),
            (Cbor::text("key_usage"), Cbor::UInt(self.key_usage as u64)),
            (Cbor::text("hw_rev_min"), Cbor::UInt(self.hw_rev_min as u64)),
            (Cbor::text("not_before"), Cbor::UInt(self.not_before)),
            (Cbor::text("not_after"), Cbor::UInt(self.not_after)),
            (Cbor::text("signature"), Cbor::bytes(self.signature.clone())),
        ])
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let b16 = |k: &str| -> Option<[u8; 16]> {
            let s = v.get(k)?.as_bytes()?;
            if s.len() != 16 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(s);
            Some(a)
        };
        let pub_bytes = v.get("public")?.as_bytes()?.to_vec();
        Some(SignerCert {
            subject_id: b16("subject_id")?,
            signer_id: b16("signer_id")?,
            public: HybridPublicKey::from_bytes(&pub_bytes)?,
            key_usage: v.get("key_usage")?.as_u64()? as u8,
            hw_rev_min: v.get("hw_rev_min")?.as_u64()? as u16,
            not_before: v.get("not_before")?.as_u64()?,
            not_after: v.get("not_after")?.as_u64()?,
            signature: v.get("signature")?.as_bytes()?.to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_cbor().to_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let v = Cbor::from_slice(b).ok()?;
        Self::from_cbor(&v)
    }
}

/// Цепочка сертификатов → CBOR-массив (поле cert_chain образа).
pub fn encode_chain(chain: &[SignerCert]) -> Vec<u8> {
    Cbor::array(chain.iter().map(|c| c.to_cbor()).collect()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    #[test]
    fn cert_roundtrip_and_issued_by() {
        let issuer = HybridKeyPair::generate().unwrap();
        let subject = HybridKeyPair::generate().unwrap();
        let mut c = SignerCert {
            subject_id: [1u8; 16],
            signer_id: key_id_of_pub(&issuer.public),
            public: subject.public.clone(),
            key_usage: USAGE_FIRMWARE_SIGN,
            hw_rev_min: 1,
            not_before: 100,
            not_after: 200,
            signature: Vec::new(),
        };
        c.signature = hybrid_sign(&issuer, &c.tbs()).unwrap();
        assert!(c.issued_by(&issuer.public));
        assert!(c.time_valid(150));
        assert!(!c.time_valid(201));
        assert!(!c.time_valid(99));
        // roundtrip
        let enc = c.encode();
        let dec = SignerCert::decode(&enc).unwrap();
        assert_eq!(dec.subject_id, c.subject_id);
        assert_eq!(dec.public.to_bytes(), c.public.to_bytes());
        assert!(dec.issued_by(&issuer.public));
        assert_eq!(dec.to_cbor().to_vec(), enc, "canonical re-encode identical");
        // другой эмитент не подходит
        let other = HybridKeyPair::generate().unwrap();
        assert!(!c.issued_by(&other.public));
        // тамперинг tbs
        let mut bad = c.clone();
        bad.not_after = 999;
        assert!(!bad.issued_by(&issuer.public));
    }
}
