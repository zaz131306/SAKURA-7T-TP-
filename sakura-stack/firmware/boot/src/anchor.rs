//! TrustAnchor — корень доверия (L0, §5.2, §22.14 ROM key fused).
//! Проверка по C-02: используется root key; цепочка проверяется; CRL —
//! ДО проверки подписи; порядок проверок по §27.2:
//! hash → цепочка/время/CRL → ГОСТ-подпись → PQ-подпись.

use crate::cert::{key_id_of_pub, SignerCert, USAGE_CA, USAGE_FIRMWARE_SIGN, USAGE_UPDATE_SIGN};
use crate::image::{
    BootError, ALG_GOST_PLUS_MLDSA65, ALG_STREEBOG_256, ALG_STREEBOG_512, HEADER_LEN,
};
use sakura_gost::hash::{constant_time_eq, streebog256, streebog512};
use sakura_hybrid::{split_hybrid_signature, HybridPublicKey};

pub struct TrustAnchor {
    /// Публичный ключ корневого CA (L0, offline HSM, §23.6).
    pub root: HybridPublicKey,
    /// CRL: отозванные subject_key_id (DM-1: bstr(16)).
    pub crl: Vec<[u8; 16]>,
}

impl TrustAnchor {
    pub fn new(root: HybridPublicKey, crl: Vec<[u8; 16]>) -> Self {
        TrustAnchor { root, crl }
    }

    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        TrustAnchor {
            root: HybridPublicKey { gost: [0u8; 64], mldsa: vec![0u8; 1952], mlkem_ek: vec![0u8; 1568] },
            crl: Vec::new(),
        }
    }

    pub fn root_key_id(&self) -> [u8; 16] {
        key_id_of_pub(&self.root)
    }

    fn in_crl(&self, kid: &[u8; 16]) -> bool {
        self.crl.iter().any(|r| r == kid)
    }

    /// Проверка цепочки сертификатов узла/оператора (leaf-first) БЕЗ
    /// ограничения keyUsage leaf-сертификата (usage проверяется вызывающим
    /// по назначению: DEVICE_IDENTITY / OPERATOR, §23.5).
    pub fn verify_chain_for_usage(
        &self,
        chain: &[SignerCert],
        expected_subject_id: &[u8; 16],
        now_s: Option<u64>,
    ) -> Result<HybridPublicKey, BootError> {
        self.verify_chain_inner(chain, expected_subject_id, now_s, false)
    }

    /// Проверка цепочки сертификатов (leaf-first):
    /// chain[0] — подписант образа (signer_id = header.signer_id),
    /// chain[n-1] — выпущен корневым CA. Возвращает публичный ключ leaf.
    pub fn verify_chain(
        &self,
        chain: &[SignerCert],
        expected_signer_id: &[u8; 16],
        now_s: Option<u64>,
    ) -> Result<HybridPublicKey, BootError> {
        self.verify_chain_inner(chain, expected_signer_id, now_s, true)
    }

    fn verify_chain_inner(
        &self,
        chain: &[SignerCert],
        expected_signer_id: &[u8; 16],
        now_s: Option<u64>,
        require_fw_usage: bool,
    ) -> Result<HybridPublicKey, BootError> {
        if chain.is_empty() {
            return Err(BootError::ChainInvalid);
        }
        // leaf: signer_id заголовка обязан совпадать с subject_id chain[0]
        if chain[0].subject_id != *expected_signer_id {
            return Err(BootError::ChainInvalid);
        }
        // проверка каждого сертификата: время → CRL → подпись эмитента
        for (i, cert) in chain.iter().enumerate() {
            if let Some(now) = now_s {
                if !cert.time_valid(now) {
                    return Err(BootError::CertExpired);
                }
            }
            let kid = cert.subject_key_id();
            if self.in_crl(&kid) {
                return Err(BootError::Revoked);
            }
            let issuer_pub = if i + 1 < chain.len() {
                // промежуточный эмитент: signer_id совпадает с key_id следующего
                if cert.signer_id != key_id_of_pub(&chain[i + 1].public) {
                    return Err(BootError::ChainInvalid);
                }
                &chain[i + 1].public
            } else {
                // вершина цепочки — корневой CA
                if cert.signer_id != self.root_key_id() {
                    return Err(BootError::ChainInvalid);
                }
                &self.root
            };
            if !cert.issued_by(issuer_pub) {
                return Err(BootError::ChainInvalid);
            }
        }
        // промежуточные сертификаты — только CA (§23.4 PKI design)
        for cert in chain.iter().skip(1) {
            if cert.key_usage != USAGE_CA {
                return Err(BootError::PolicyViolationUsage);
            }
        }
        // keyUsage leaf-сертификата: подписание прошивок/обновлений
        if require_fw_usage
            && !matches!(chain[0].key_usage, USAGE_FIRMWARE_SIGN | USAGE_UPDATE_SIGN)
        {
            return Err(BootError::PolicyViolationUsage);
        }
        Ok(chain[0].public.clone())
    }

    /// Проверка гибридной подписи сообщения с различением ГОСТ/PQ-ошибок
    /// (§27.2 split_hybrid_signature). Leaf-сертификат — подписант прошивок.
    pub fn verify_message(
        &self,
        data: &[u8],
        chain: &[SignerCert],
        signer_id: &[u8; 16],
        signature: &[u8],
        alg: u8,
        now_s: Option<u64>,
    ) -> Result<(), BootError> {
        self.verify_message_inner(data, chain, signer_id, signature, alg, now_s, true)
    }

    /// Проверка подписи сообщения ключом ИДЕНТИЧНОСТИ устройства
    /// (attestation, сессии): leaf-сертификат — DEVICE_IDENTITY/OPERATOR.
    pub fn verify_message_identity(
        &self,
        data: &[u8],
        chain: &[SignerCert],
        signer_id: &[u8; 16],
        signature: &[u8],
        alg: u8,
        now_s: Option<u64>,
    ) -> Result<(), BootError> {
        self.verify_message_inner(data, chain, signer_id, signature, alg, now_s, false)
    }

    fn verify_message_inner(
        &self,
        data: &[u8],
        chain: &[SignerCert],
        signer_id: &[u8; 16],
        signature: &[u8],
        alg: u8,
        now_s: Option<u64>,
        require_fw_usage: bool,
    ) -> Result<(), BootError> {
        let leaf = self.verify_chain_inner(chain, signer_id, now_s, require_fw_usage)?;
        if alg != ALG_GOST_PLUS_MLDSA65 {
            return Err(BootError::UnsupportedAlgorithm);
        }
        let (gost_sig, pq_sig) = split_hybrid_signature(signature, alg).map_err(|e| match e {
            sakura_hybrid::HybridSignError::SignatureTooShort => BootError::SignatureTooShort,
            _ => BootError::UnsupportedAlgorithm,
        })?;
        let digest = streebog256(data);
        let mut gs = [0u8; 64];
        gs.copy_from_slice(gost_sig);
        if !sakura_gost::gost3410::verify(&leaf.gost, &digest, &gs) {
            return Err(BootError::GostSignatureInvalid);
        }
        if !sakura_pq::mldsa65_verify(&leaf.mldsa, data, b"", pq_sig) {
            return Err(BootError::PqSignatureInvalid);
        }
        Ok(())
    }

    /// Проверка образа по §27.2 (C-02):
    /// 1. фактический хэш payload == expected_hash (constant-time);
    /// 2. цепочка/время/CRL;
    /// 3. подпись по заголовок||payload: ГОСТ-часть, затем PQ-часть.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_hybrid(
        &self,
        payload: &[u8],
        expected_hash: &[u8],
        hash_alg: u8,
        chain: &[SignerCert],
        signer_id: &[u8; 16],
        header114: &[u8; HEADER_LEN],
        signature: &[u8],
        sig_alg: u8,
        now_s: Option<u64>,
    ) -> Result<(), BootError> {
        // 1. хэш (C-02)
        let actual = match hash_alg {
            ALG_STREEBOG_256 => streebog256(payload).to_vec(),
            ALG_STREEBOG_512 => streebog512(payload).to_vec(),
            _ => return Err(BootError::UnsupportedHashAlg),
        };
        if !constant_time_eq(&actual, expected_hash) {
            return Err(BootError::HashMismatch);
        }
        // 2–3. цепочка и подпись по полному покрытию
        let mut data = Vec::with_capacity(HEADER_LEN + payload.len());
        data.extend_from_slice(header114);
        data.extend_from_slice(payload);
        self.verify_message(&data, chain, signer_id, signature, sig_alg, now_s)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cert::{encode_chain, USAGE_FIRMWARE_SIGN};
    use crate::image::{
        parse_image, DeviceState, ImageHeader, FLAG_SIGNED, IMAGE_TYPE_KERNEL,
    };
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    pub(crate) fn build_signed_image(
        root: &HybridKeyPair,
        signer: &HybridKeyPair,
        signer_cert: &SignerCert,
        payload: &[u8],
        version: u32,
        rollback: u32,
        timestamp: u64,
        min_hw_rev: u16,
        hash_alg: u8,
    ) -> Vec<u8> {
        let chain = encode_chain(std::slice::from_ref(signer_cert));
        let h = ImageHeader {
            version,
            min_hw_rev,
            image_type: IMAGE_TYPE_KERNEL,
            flags: FLAG_SIGNED,
            payload_size: payload.len() as u32,
            payload_hash_alg: hash_alg,
            payload_hash: {
                let mut x = [0u8; 64];
                match hash_alg {
                    ALG_STREEBOG_256 => x[..32].copy_from_slice(&streebog256(payload)),
                    _ => x.copy_from_slice(&streebog512(payload)),
                }
                x
            },
            signer_id: signer_cert.subject_id,
            signature_alg: ALG_GOST_PLUS_MLDSA65,
            rollback_counter: rollback,
            timestamp,
        };
        let hdr = h.header_bytes(chain.len() as u16, sakura_hybrid::HYBRID_SIG_LEN as u16);
        let mut data = Vec::new();
        data.extend_from_slice(&hdr);
        data.extend_from_slice(payload);
        let sig = hybrid_sign(signer, &crate::image::image_sign_data(&hdr, payload)).unwrap();
        data.extend_from_slice(&chain);
        data.extend_from_slice(&sig);
        let _ = root;
        data
    }

    fn fixture() -> (HybridKeyPair, HybridKeyPair, SignerCert, TrustAnchor) {
        let root = HybridKeyPair::generate().unwrap();
        let signer = HybridKeyPair::generate().unwrap();
        let mut cert = SignerCert {
            subject_id: [7u8; 16],
            signer_id: key_id_of_pub(&root.public),
            public: signer.public.clone(),
            key_usage: USAGE_FIRMWARE_SIGN,
            hw_rev_min: 1,
            not_before: 1_000,
            not_after: 2_000_000_000,
            signature: Vec::new(),
        };
        cert.signature = hybrid_sign(&root, &cert.tbs()).unwrap();
        let anchor = TrustAnchor::new(root.public.clone(), Vec::new());
        (root, signer, cert, anchor)
    }

    #[test]
    fn full_image_verify_ok() {
        let (root, signer, cert, anchor) = fixture();
        let img_bytes =
            build_signed_image(&root, &signer, &cert, b"kernel payload", 3, 1, 100_000, 1, ALG_STREEBOG_256);
        let img = parse_image(&img_bytes).unwrap();
        let dev = DeviceState { hw_rev: 2, now_s: Some(100_001), min_versions: [1, 0, 0, 0] };
        img.verify(&anchor, &dev).unwrap();
        // Стрибог-512 вариант
        let img_bytes512 =
            build_signed_image(&root, &signer, &cert, b"kernel payload", 3, 1, 100_000, 1, ALG_STREEBOG_512);
        let img512 = parse_image(&img_bytes512).unwrap();
        img512.verify(&anchor, &dev).unwrap();
    }

    #[test]
    fn tamper_payload_rejected() {
        let (root, signer, cert, anchor) = fixture();
        let mut img_bytes =
            build_signed_image(&root, &signer, &cert, b"kernel payload", 3, 1, 100_000, 1, ALG_STREEBOG_256);
        // тамперинг payload (после заголовка)
        img_bytes[HEADER_LEN + 3] ^= 0xFF;
        let img = parse_image(&img_bytes).unwrap();
        let dev = DeviceState { hw_rev: 2, now_s: Some(100_001), min_versions: [1, 0, 0, 0] };
        assert_eq!(img.verify(&anchor, &dev), Err(BootError::HashMismatch));
    }

    #[test]
    fn rollback_and_hwrev_and_time() {
        let (root, signer, cert, anchor) = fixture();
        let img_bytes =
            build_signed_image(&root, &signer, &cert, b"k", 3, 1, 100_000, 2, ALG_STREEBOG_256);
        let img = parse_image(&img_bytes).unwrap();
        // rollback: counter 1 < min_version 2 для KERNEL (type 2 → индекс 1)
        let dev = DeviceState { hw_rev: 3, now_s: Some(100_001), min_versions: [0, 2, 0, 0] };
        assert_eq!(img.verify(&anchor, &dev), Err(BootError::RollbackRejected));
        // hw_rev: min_hw_rev 2 > device 1 → HwRevMismatch
        let dev2 = DeviceState { hw_rev: 1, now_s: Some(100_001), min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor, &dev2), Err(BootError::HwRevMismatch));
        // timestamp в будущем (> now+60) → TimestampInvalid
        let dev3 = DeviceState { hw_rev: 3, now_s: Some(99_000), min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor, &dev3), Err(BootError::TimestampInvalid));
        // корректное устройство — OK
        let dev4 = DeviceState { hw_rev: 3, now_s: Some(100_001), min_versions: [1, 0, 0, 0] };
        img.verify(&anchor, &dev4).unwrap();
    }

    #[test]
    fn revoked_cert_rejected_before_signature() {
        let (root, signer, mut cert, _) = fixture();
        let img_bytes =
            build_signed_image(&root, &signer, &cert, b"k", 3, 1, 100_000, 1, ALG_STREEBOG_256);
        // CRL с subject_key_id сертификата
        let anchor = TrustAnchor::new(root.public.clone(), vec![cert.subject_key_id()]);
        cert.signature.clear(); // даже без подписи — сначала Revoked (порядок C-02)
        let img = parse_image(&img_bytes).unwrap();
        let dev = DeviceState { hw_rev: 2, now_s: Some(100_001), min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor, &dev), Err(BootError::Revoked));
    }

    #[test]
    fn expired_cert_and_bad_chain() {
        let (root, signer, cert, _) = fixture();
        let img_bytes =
            build_signed_image(&root, &signer, &cert, b"k", 3, 1, 100_000, 1, ALG_STREEBOG_256);
        let img = parse_image(&img_bytes).unwrap();
        // время за пределами not_after → CertExpired
        let anchor = TrustAnchor::new(root.public.clone(), Vec::new());
        let dev = DeviceState { hw_rev: 2, now_s: Some(3_000_000_000), min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor, &dev), Err(BootError::CertExpired));
        // чужой root → ChainInvalid
        let other_root = HybridKeyPair::generate().unwrap();
        let anchor2 = TrustAnchor::new(other_root.public.clone(), Vec::new());
        let dev2 = DeviceState { hw_rev: 2, now_s: Some(100_001), min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor2, &dev2), Err(BootError::ChainInvalid));
        let _ = signer;
    }

    #[test]
    fn signature_split_errors() {
        let (root, signer, cert, anchor) = fixture();
        let mut img_bytes =
            build_signed_image(&root, &signer, &cert, b"k", 3, 1, 100_000, 1, ALG_STREEBOG_256);
        // порча ГОСТ-части подписи (после заголовка+payload+chain)
        let sig_off = img_bytes.len() - sakura_hybrid::HYBRID_SIG_LEN;
        img_bytes[sig_off + 5] ^= 1;
        let img = parse_image(&img_bytes).unwrap();
        let dev = DeviceState { hw_rev: 2, now_s: Some(100_001), min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor, &dev), Err(BootError::GostSignatureInvalid));
        // порча PQ-части
        let mut img_bytes2 =
            build_signed_image(&root, &signer, &cert, b"k", 3, 1, 100_000, 1, ALG_STREEBOG_256);
        let sig_off2 = img_bytes2.len() - sakura_hybrid::HYBRID_SIG_LEN;
        img_bytes2[sig_off2 + 64 + 10] ^= 1;
        let img2 = parse_image(&img_bytes2).unwrap();
        assert_eq!(img2.verify(&anchor, &dev), Err(BootError::PqSignatureInvalid));
    }
}
