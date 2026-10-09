//! sakura-boot — L0 Trust Anchor (§5.2):
//! - [`image`] — формат образа §22.1.2 и парсер по смещениям (C-08);
//! - [`cert`] — сертификаты подписанта (CBOR-профиль §23.5);
//! - [`anchor`] — TrustAnchor: hash → цепочка/время/CRL → ГОСТ → PQ (C-02, §27.2);
//! - [`pcr`] — measured boot, PCR 0–15 (§22.16);
//! - [`rollback`] — active/pending rollback counters (BC-24);
//! - [`fsm`] — Boot FSM (§13.16.1): 3 неудачи → RECOVERY_MODE, tamper → LOCKDOWN+ZEROIZE;
//! - [`keyrelease`] — политика выпуска ключей HSM (§13.7, §22.14).
#![forbid(unsafe_code)]

pub mod anchor;
pub mod bundle;
pub mod cert;
pub mod fsm;
pub mod image;
pub mod keyrelease;
pub mod pcr;
pub mod rollback;

pub use anchor::TrustAnchor;
pub use bundle::{RosterEntry, TrustBundle};
pub use cert::SignerCert;
pub use fsm::{BootEvent, BootFsm, BootState};
pub use image::{BootError, DeviceState, ImageHeader, ParsedImage};
pub use keyrelease::{check_key_release, KeyReleaseError, KeyReleasePolicy};
pub use pcr::PcrBank;
pub use rollback::RollbackStore;

use image::parse_image;

/// Измерение образа в PCR (measured boot log, §22.14):
/// hash образа расширяет соответствующий PCR.
pub fn measure(pcrs: &mut PcrBank, idx: u8, image_bytes: &[u8]) {
    let digest = sakura_gost::hash::streebog256(image_bytes);
    pcrs.extend(idx, &digest);
}

/// Полная проверка + измерение одного звена цепочки загрузки.
pub fn verify_and_measure<'a>(
    pcrs: &mut PcrBank,
    pcr_idx: u8,
    image_bytes: &'a [u8],
    anchor: &TrustAnchor,
    device: &DeviceState,
) -> Result<ParsedImage<'a>, BootError> {
    let img = parse_image(image_bytes)?;
    img.verify(anchor, device)?;
    measure(pcrs, pcr_idx, image_bytes);
    Ok(img)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{ALG_STREEBOG_256, FLAG_SIGNED};
    use crate::anchor::tests::build_signed_image;
    use crate::cert::{key_id_of_pub, SignerCert, USAGE_FIRMWARE_SIGN};
    use crate::image::{ALG_STREEBOG_256 as A256, IMAGE_TYPE_KERNEL};
    use crate::pcr::PCR_KERNEL;
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    #[test]
    fn chain_verify_and_measure() {
        let root = HybridKeyPair::generate().unwrap();
        let signer = HybridKeyPair::generate().unwrap();
        let mut cert = SignerCert {
            subject_id: [4u8; 16],
            signer_id: key_id_of_pub(&root.public),
            public: signer.public.clone(),
            key_usage: USAGE_FIRMWARE_SIGN,
            hw_rev_min: 1,
            not_before: 0,
            not_after: u64::MAX,
            signature: Vec::new(),
        };
        cert.signature = hybrid_sign(&root, &cert.tbs()).unwrap();
        let anchor = TrustAnchor::new(root.public.clone(), Vec::new());
        let img = build_signed_image(&root, &signer, &cert, b"payload-x", 1, 0, 0, 1, A256);

        let mut pcrs = PcrBank::new();
        let dev = DeviceState { hw_rev: 1, now_s: None, min_versions: [0; 4] };
        let parsed =
            verify_and_measure(&mut pcrs, PCR_KERNEL, &img, &anchor, &dev).unwrap();
        assert_eq!(parsed.header.image_type, IMAGE_TYPE_KERNEL);
        assert_eq!(parsed.header.flags & FLAG_SIGNED, FLAG_SIGNED);
        assert_eq!(parsed.header.payload_hash_alg, ALG_STREEBOG_256);
        // PCR изменён измерением
        assert_ne!(pcrs.get(PCR_KERNEL), [0u8; 32]);
        // повторная загрузка того же образа детерминированно удлиняет цепочку
        let pcr_after_first = pcrs.get(PCR_KERNEL);
        verify_and_measure(&mut pcrs, PCR_KERNEL, &img, &anchor, &dev).unwrap();
        assert_ne!(pcrs.get(PCR_KERNEL), pcr_after_first);
    }
}
