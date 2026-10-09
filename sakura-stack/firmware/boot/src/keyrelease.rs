//! Key release policy (§13.7, §22.14): HSM выпускает операционные ключи
//! ТОЛЬКО при соответствии измерений политике.

use crate::pcr::PcrBank;
use crate::rollback::RollbackStore;
use sakura_common::cbor::Cbor;
use sakura_gost::hash::streebog256;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyReleaseError {
    PcrMismatch(u8),
    MinVersionViolated(u8),
    HsmStatusBad,
    ModelNotAllowed,
    TimeQualityBad,
    TamperFlag,
    PendingRollbackUncommitted,
}

/// Политика выпуска ключей: ожидаемые PCR, минимальные версии,
/// HSM status, model allowlist, time quality, tamper flags (§13.7).
#[derive(Clone, Debug, Default)]
pub struct KeyReleasePolicy {
    /// Ожидаемые значения PCR (индекс → 32 Б); None-значения не проверяются.
    pub expected_pcrs: BTreeMap<u8, [u8; 32]>,
    /// Минимальные активные версии по типам образов (image_type → version).
    pub min_versions: BTreeMap<u8, u32>,
    /// Требуемый HSM status из attestation-отчёта.
    pub hsm_status_required: String,
    /// Allowlist хэшей моделей (Стрибог-512 → 64 Б, DM-1 Model.model_hash);
    /// пустой список = модели не используются.
    pub model_allowlist: Vec<[u8; 64]>,
    /// Допустимое качество времени (§12.1: LOCKED / HOLDOVER).
    pub time_quality_allowed: Vec<String>,
    /// Требуемое отсутствие tamper-флагов.
    pub require_no_tamper: bool,
}

impl KeyReleasePolicy {
    pub fn policy_hash(&self) -> [u8; 32] {
        self.to_cbor_vec().map(|b| streebog256(&b)).unwrap_or([0u8; 32])
    }

    pub fn to_cbor(&self) -> Cbor {
        Cbor::map(vec![
            (
                Cbor::text("expected_pcrs"),
                Cbor::map(
                    self.expected_pcrs
                        .iter()
                        .map(|(k, v)| (Cbor::UInt(*k as u64), Cbor::bytes(v.to_vec())))
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                Cbor::text("min_versions"),
                Cbor::map(
                    self.min_versions
                        .iter()
                        .map(|(k, v)| (Cbor::UInt(*k as u64), Cbor::UInt(*v as u64)))
                        .collect::<Vec<_>>(),
                ),
            ),
            (Cbor::text("hsm_status_required"), Cbor::text(self.hsm_status_required.clone())),
            (
                Cbor::text("model_allowlist"),
                Cbor::array(self.model_allowlist.iter().map(|m| Cbor::bytes(m.to_vec())).collect()),
            ),
            (
                Cbor::text("time_quality_allowed"),
                Cbor::array(self.time_quality_allowed.iter().map(|t| Cbor::text(t.clone())).collect()),
            ),
            (Cbor::text("require_no_tamper"), Cbor::Bool(self.require_no_tamper)),
        ])
    }

    pub fn to_cbor_vec(&self) -> Option<Vec<u8>> {
        Some(self.to_cbor().to_vec())
    }
}

/// Проверка соответствия состояния устройства политике выпуска ключей.
/// Вызывается на стадии KEY_RELEASE_POLICY_CHECK (§13.16.1).
pub fn check_key_release(
    policy: &KeyReleasePolicy,
    pcrs: &PcrBank,
    hsm_report: &Cbor,
    rollback: &RollbackStore,
    loaded_models: &[[u8; 64]],
    time_quality: &str,
    tamper: bool,
) -> Result<(), KeyReleaseError> {
    if policy.require_no_tamper && tamper {
        return Err(KeyReleaseError::TamperFlag);
    }
    // 1. ожидаемые PCR (§13.7)
    for (idx, want) in &policy.expected_pcrs {
        if &pcrs.get(*idx) != want {
            return Err(KeyReleaseError::PcrMismatch(*idx));
        }
    }
    // 2. минимальные версии (активные rollback-счётчики)
    for (itype, minv) in &policy.min_versions {
        if rollback.active(*itype) < *minv {
            return Err(KeyReleaseError::MinVersionViolated(*itype));
        }
        // незакоммиченный pending на стадии выпуска ключей — нарушение
        // последовательности UPDATE FSM (§13.16.2)
        if rollback.pending(*itype).is_some() {
            return Err(KeyReleaseError::PendingRollbackUncommitted);
        }
    }
    // 3. HSM status из attestation-отчёта
    let status = hsm_report.get("hsm_status").and_then(|v| v.as_text()).unwrap_or("");
    if status != policy.hsm_status_required {
        return Err(KeyReleaseError::HsmStatusBad);
    }
    // 4. model allowlist (BC-35: только аттестованные модели)
    for m in loaded_models {
        if !policy.model_allowlist.iter().any(|a| a == m) {
            return Err(KeyReleaseError::ModelNotAllowed);
        }
    }
    // 5. time quality (§12.1: LOCKED/HOLDOVER допустимы, FREE — нет)
    if !policy.time_quality_allowed.iter().any(|t| t == time_quality) {
        return Err(KeyReleaseError::TimeQualityBad);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcr::{PcrBank, PCR_KERNEL};

    fn hsm_ok_report() -> Cbor {
        Cbor::map(vec![(Cbor::text("hsm_status"), Cbor::text("OK"))])
    }

    fn base_policy(pcrs: &PcrBank) -> KeyReleasePolicy {
        let mut expected = BTreeMap::new();
        expected.insert(PCR_KERNEL, pcrs.get(PCR_KERNEL));
        KeyReleasePolicy {
            expected_pcrs: expected,
            min_versions: BTreeMap::new(),
            hsm_status_required: "OK".to_owned(),
            model_allowlist: Vec::new(),
            time_quality_allowed: vec!["LOCKED".to_owned(), "HOLDOVER".to_owned()],
            require_no_tamper: true,
        }
    }

    #[test]
    fn release_flow() {
        let mut pcrs = PcrBank::new();
        pcrs.extend(PCR_KERNEL, b"kernel-v3");
        let rb = RollbackStore::new([3u8; 32]);
        let policy = base_policy(&pcrs);
        // OK
        check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &[], "LOCKED", false).unwrap();
        // tamper
        assert_eq!(
            check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &[], "LOCKED", true),
            Err(KeyReleaseError::TamperFlag)
        );
        // PCR mismatch
        let mut pcrs2 = PcrBank::new();
        pcrs2.extend(PCR_KERNEL, b"kernel-EVIL");
        assert_eq!(
            check_key_release(&policy, &pcrs2, &hsm_ok_report(), &rb, &[], "LOCKED", false),
            Err(KeyReleaseError::PcrMismatch(PCR_KERNEL))
        );
        // HSM status
        let bad_hsm = Cbor::map(vec![(Cbor::text("hsm_status"), Cbor::text("TAMPER"))]);
        assert_eq!(
            check_key_release(&policy, &pcrs, &bad_hsm, &rb, &[], "LOCKED", false),
            Err(KeyReleaseError::HsmStatusBad)
        );
        // time quality FREE — недопустимо (§12.1)
        assert_eq!(
            check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &[], "FREE", false),
            Err(KeyReleaseError::TimeQualityBad)
        );
        // model не из allowlist
        let models = vec![[0xAA; 64]];
        assert_eq!(
            check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &models, "LOCKED", false),
            Err(KeyReleaseError::ModelNotAllowed)
        );
        // model из allowlist — OK
        let mut policy2 = base_policy(&pcrs);
        policy2.model_allowlist = models.clone();
        check_key_release(&policy2, &pcrs, &hsm_ok_report(), &rb, &models, "HOLDOVER", false)
            .unwrap();
    }

    #[test]
    fn min_versions_and_pending() {
        let pcrs = PcrBank::new();
        let mut policy = base_policy(&pcrs);
        policy.expected_pcrs.clear();
        policy.min_versions.insert(2, 5);
        let mut rb = RollbackStore::new([3u8; 32]);
        assert_eq!(
            check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &[], "LOCKED", false),
            Err(KeyReleaseError::MinVersionViolated(2))
        );
        rb.set_pending(2, 5).unwrap();
        rb.commit_pending(2).unwrap();
        check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &[], "LOCKED", false).unwrap();
        // незакоммиченный pending → отказ
        rb.set_pending(2, 6).unwrap();
        assert_eq!(
            check_key_release(&policy, &pcrs, &hsm_ok_report(), &rb, &[], "LOCKED", false),
            Err(KeyReleaseError::PendingRollbackUncommitted)
        );
    }

    #[test]
    fn policy_hash_stable() {
        let p = KeyReleasePolicy { hsm_status_required: "OK".into(), ..Default::default() };
        let h1 = p.policy_hash();
        let h2 = p.policy_hash();
        assert_eq!(h1, h2);
        let mut p2 = p.clone();
        p2.hsm_status_required = "BAD".into();
        assert_ne!(h1, p2.policy_hash());
    }
}
