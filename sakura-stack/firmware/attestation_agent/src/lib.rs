//! Attestation (BC-19 / ATT-001, §13.7, §22.6, §27.8):
//!
//! ```text
//! MUST: attestation report использует CBOR/COSE_Sign1 или утверждённый
//!       canonical профиль.
//! MUST: подпись имеет переменную длину по hybrid-профилю.
//! MUST: фиксированная длина 96 Б запрещена как универсальное требование.
//! MUST: verifier проверяет signature_alg, signer certificate chain, nonce,
//!       PCR set, policy hash, expiry и revocation status.
//! MUST: размер буфера подписи определяется профилем КР-1 и передаётся
//!       вызывающей стороной.
//! ```
//!
//! Схема отчёта — §13.7 (12+ полей); подпись — COSE_Sign1 (RFC 8152),
//! Sig_structure = ["Signature1", protected, external_aad, payload].
#![forbid(unsafe_code)]

use sakura_boot::cert::SignerCert;
use sakura_boot::anchor::TrustAnchor;
use sakura_boot::image::BootError;
use sakura_common::cbor::{Cbor, CborError};
use sakura_common::time;
use sakura_gost::hash::streebog256;
use sakura_hsm::{HsmBackend, KeyHandle, SessionId};

pub const COSE_SIGN1_TAG: u64 = 18;
pub const ALG_GOST_PLUS_MLDSA65: i64 = sakura_gost::ALG_GOST_PLUS_MLDSA65 as i64;
/// Срок годности отчёта (§13.19.2 RequestAttestation): ≤60 с.
pub const REPORT_TTL_S: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationError {
    CborEncode,
    SignFailed,
    VerifyFailed,
    BufferTooSmall,
    Hsm(sakura_hsm::HsmError),
    Chain(BootError),
    NonceMismatch,
    Expired,
    PcrMismatch,
    PolicyHashMismatch,
    HsmStatusBad,
    ModelNotAllowed,
    AlgMismatch,
}

/// Attestation report (§13.7). Поля — owned (хост-профиль); no_std-профиль
/// (§27.8) — slice-based encode в буфер вызывающей стороны.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationReport {
    pub device_id: Vec<u8>,
    pub hw_rev: u16,
    pub fw_versions: Vec<(String, String)>,
    pub pcrs: Vec<(u8, [u8; 32])>,
    pub boot_mode: String,
    pub rollback_counters: Vec<(String, u64)>,
    pub hsm_status: String,
    pub time_sync_quality: String,
    pub model_hashes: Vec<Vec<u8>>,
    pub policy_hash: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature_alg: u16,
    pub timestamp_s: u64,
}

impl AttestationReport {
    /// Payload отчёта (canonical CBOR map) — БЕЗ поля signature:
    /// подпись покрывает payload (DM-1 §13.18.3 п.2 — та же семантика).
    pub fn payload_cbor(&self) -> Cbor {
        let items = vec![
            (Cbor::text("device_id"), Cbor::bytes(self.device_id.clone())),
            (Cbor::text("hw_rev"), Cbor::text(self.hw_rev.to_string())),
            (
                Cbor::text("fw_versions"),
                Cbor::map(
                    self.fw_versions
                        .iter()
                        .map(|(k, v)| (Cbor::text(k.clone()), Cbor::text(v.clone())))
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                Cbor::text("pcrs"),
                Cbor::map(
                    self.pcrs
                        .iter()
                        .map(|(i, p)| (Cbor::UInt(*i as u64), Cbor::bytes(p.to_vec())))
                        .collect::<Vec<_>>(),
                ),
            ),
            (Cbor::text("boot_mode"), Cbor::text(self.boot_mode.clone())),
            (
                Cbor::text("rollback_counters"),
                Cbor::map(
                    self.rollback_counters
                        .iter()
                        .map(|(k, v)| (Cbor::text(k.clone()), Cbor::UInt(*v)))
                        .collect::<Vec<_>>(),
                ),
            ),
            (Cbor::text("hsm_status"), Cbor::text(self.hsm_status.clone())),
            (Cbor::text("time_sync_quality"), Cbor::text(self.time_sync_quality.clone())),
            (
                Cbor::text("model_hashes"),
                Cbor::array(self.model_hashes.iter().map(|m| Cbor::bytes(m.clone())).collect()),
            ),
            (Cbor::text("policy_hash"), Cbor::bytes(self.policy_hash.clone())),
            (Cbor::text("nonce"), Cbor::bytes(self.nonce.clone())),
            (Cbor::text("signature_alg"), Cbor::UInt(self.signature_alg as u64)),
            (Cbor::text("timestamp_s"), Cbor::UInt(self.timestamp_s)),
        ];
        Cbor::map(items)
    }

    pub fn payload_bytes(&self) -> Vec<u8> {
        self.payload_cbor().to_vec()
    }

    /// Полный CBOR отчёта с подписью (§13.7: поле signature — bstr
    /// переменной длины, BC-19).
    pub fn to_cbor_with_signature(&self, signature: &[u8]) -> Cbor {
        let mut items = match self.payload_cbor() {
            Cbor::Map(v) => v,
            _ => unreachable!(),
        };
        items.push((Cbor::text("signature"), Cbor::bytes(signature.to_vec())));
        items.sort_by(|a, b| {
            let ka = a.0.to_vec();
            let kb = b.0.to_vec();
            ka.len().cmp(&kb.len()).then_with(|| ka.cmp(&kb))
        });
        Cbor::Map(items)
    }
}

/// COSE_Sign1 (RFC 8152): tag 18 → [protected, unprotected, payload, signature].
pub fn cose_sign1(protected: &[u8], payload: &[u8], signature: &[u8]) -> Cbor {
    Cbor::Tag(
        COSE_SIGN1_TAG,
        Box::new(Cbor::array(vec![
            Cbor::bytes(protected.to_vec()),
            Cbor::empty_map(),
            Cbor::bytes(payload.to_vec()),
            Cbor::bytes(signature.to_vec()),
        ])),
    )
}

/// Sig_structure для COSE_Sign1: ["Signature1", protected, external_aad, payload].
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    Cbor::array(vec![
        Cbor::text("Signature1"),
        Cbor::bytes(protected.to_vec()),
        Cbor::bytes(Vec::new()),
        Cbor::bytes(payload.to_vec()),
    ])
    .to_vec()
}

/// Protected header: {"alg": 0x10 (ГОСТ+ML-DSA-65), "kid": device_id}.
pub fn protected_header(alg: i64, kid: &[u8]) -> Vec<u8> {
    Cbor::map(vec![
        (Cbor::text("alg"), Cbor::int(alg)),
        (Cbor::text("kid"), Cbor::bytes(kid.to_vec())),
    ])
    .to_vec()
}

/// Разбор COSE_Sign1 → (protected, payload, signature).
pub fn parse_cose_sign1(v: &Cbor) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CborError> {
    let inner = match v {
        Cbor::Tag(COSE_SIGN1_TAG, b) => b.as_ref(),
        Cbor::Array(_) => v,
        _ => return Err(CborError::UnknownSimple(0)),
    };
    let arr = match inner {
        Cbor::Array(a) if a.len() == 4 => a,
        _ => return Err(CborError::UnknownSimple(1)),
    };
    Ok((
        arr[0].as_bytes().ok_or(CborError::UnknownSimple(2))?.to_vec(),
        arr[2].as_bytes().ok_or(CborError::UnknownSimple(3))?.to_vec(),
        arr[3].as_bytes().ok_or(CborError::UnknownSimple(4))?.to_vec(),
    ))
}

// ---------------- FSM (§13.16.3) ----------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationFsmState {
    Idle,
    ReceiveNonce,
    CollectPcrs,
    CollectHsmStatus,
    CollectModelHashes,
    SerializeCbor,
    SignCoseSign1,
    ReturnReport,
    Error,
}

pub struct AttestationAgent {
    pub state: AttestationFsmState,
    device_id: Vec<u8>,
    hw_rev: u16,
    key: KeyHandle,
}

impl AttestationAgent {
    pub fn new(device_id: Vec<u8>, hw_rev: u16, key: KeyHandle) -> Self {
        AttestationAgent { state: AttestationFsmState::Idle, device_id, hw_rev, key }
    }

    /// Полный цикл IDLE → … → RETURN_REPORT (§13.16.3).
    /// Подпись — через HSM (явная сессия, C-04); буфер подписи предоставляет
    /// вызывающая сторона (BC-18/BC-19: размер = HYBRID_SIG_LEN по КР-1).
    pub fn produce<H: HsmBackend>(
        &mut self,
        hsm: &mut H,
        sid: SessionId,
        nonce: &[u8],
        collect: &ReportInputs,
        sig_out: &mut [u8],
    ) -> Result<Vec<u8>, AttestationError> {
        self.state = AttestationFsmState::ReceiveNonce;
        if nonce.len() < 16 {
            self.state = AttestationFsmState::Error;
            return Err(AttestationError::CborEncode);
        }

        self.state = AttestationFsmState::CollectPcrs;
        let pcrs = collect.pcrs.clone();

        self.state = AttestationFsmState::CollectHsmStatus;
        // HSM status — из attest(sid, nonce) (C-04: явная сессия)
        let mut hsm_report_buf = [0u8; 1024];
        let n = hsm
            .attest(sid, nonce, &mut hsm_report_buf)
            .map_err(AttestationError::Hsm)?;
        let hsm_report =
            Cbor::from_slice(&hsm_report_buf[..n]).map_err(|_| AttestationError::CborEncode)?;
        let hsm_status = hsm_report
            .get("hsm_status")
            .and_then(|v| v.as_text())
            .unwrap_or("UNKNOWN")
            .to_owned();

        self.state = AttestationFsmState::CollectModelHashes;
        let report = AttestationReport {
            device_id: self.device_id.clone(),
            hw_rev: self.hw_rev,
            fw_versions: collect.fw_versions.clone(),
            pcrs,
            boot_mode: collect.boot_mode.clone(),
            rollback_counters: collect.rollback_counters.clone(),
            hsm_status,
            time_sync_quality: collect.time_sync_quality.clone(),
            model_hashes: collect.model_hashes.clone(),
            policy_hash: collect.policy_hash.clone(),
            nonce: nonce.to_vec(),
            signature_alg: ALG_GOST_PLUS_MLDSA65 as u16,
            timestamp_s: time::unix_s(),
        };

        self.state = AttestationFsmState::SerializeCbor;
        let payload = report.payload_bytes();
        let protected = protected_header(ALG_GOST_PLUS_MLDSA65, &self.device_id);

        self.state = AttestationFsmState::SignCoseSign1;
        let to_sign = sig_structure(&protected, &payload);
        if sig_out.len() < sakura_hybrid::HYBRID_SIG_LEN {
            self.state = AttestationFsmState::Error;
            return Err(AttestationError::BufferTooSmall); // BC-19
        }
        let sig_len = hsm.sign(sid, self.key, &to_sign, sig_out).map_err(AttestationError::Hsm)?;

        self.state = AttestationFsmState::ReturnReport;
        let cose = cose_sign1(&protected, &payload, &sig_out[..sig_len]);
        let full_report = report.to_cbor_with_signature(&sig_out[..sig_len]);
        // возвращаем COSE_Sign1 (нормативный формат); full map — для debug
        let _ = full_report;
        Ok(cose.to_vec())
    }
}

/// Входные данные для сборки отчёта (поставляются узлом).
#[derive(Clone, Debug)]
pub struct ReportInputs {
    pub fw_versions: Vec<(String, String)>,
    pub pcrs: Vec<(u8, [u8; 32])>,
    pub boot_mode: String,
    pub rollback_counters: Vec<(String, u64)>,
    pub time_sync_quality: String,
    pub model_hashes: Vec<Vec<u8>>,
    pub policy_hash: Vec<u8>,
}

// ---------------- Verifier (ATT-001) ----------------

/// Ожидаемые значения для проверки (policy §13.7).
#[derive(Clone, Debug)]
pub struct VerifyExpectations<'a> {
    pub nonce: &'a [u8],
    pub expected_pcrs: &'a [(u8, [u8; 32])],
    pub policy_hash: &'a [u8],
    pub hsm_status_required: &'a str,
    pub model_allowlist: &'a [[u8; 64]],
    pub now_s: u64,
    pub max_age_s: u64,
    pub min_fw_versions: &'a [(String, u32)],
}

/// Проверка COSE_Sign1-отчёта: signature_alg, цепочка сертификата подписанта,
/// nonce, PCR set, policy hash, expiry, revocation (ATT-001 MUST).
pub fn verify_report(
    cose_bytes: &[u8],
    device_cert_chain: &[SignerCert],
    anchor: &TrustAnchor,
    expect: &VerifyExpectations<'_>,
) -> Result<AttestationReport, AttestationError> {
    let cose = Cbor::from_slice(cose_bytes).map_err(|_| AttestationError::CborEncode)?;
    let (protected, payload, signature) =
        parse_cose_sign1(&cose).map_err(|_| AttestationError::CborEncode)?;

    // 1. signature_alg из protected header
    let prot = Cbor::from_slice(&protected).map_err(|_| AttestationError::CborEncode)?;
    let alg = prot.get("alg").and_then(|v| v.as_i64()).ok_or(AttestationError::AlgMismatch)?;
    if alg != ALG_GOST_PLUS_MLDSA65 {
        return Err(AttestationError::AlgMismatch);
    }

    // 2. signer certificate chain + revocation (через TrustAnchor)
    if device_cert_chain.is_empty() {
        return Err(AttestationError::Chain(BootError::ChainInvalid));
    }
    let signer_id = device_cert_chain[0].subject_id;
    let to_verify = sig_structure(&protected, &payload);
    anchor
        .verify_message_identity(
            &to_verify,
            device_cert_chain,
            &signer_id,
            &signature,
            sakura_gost::ALG_GOST_PLUS_MLDSA65,
            Some(expect.now_s),
        )
        .map_err(|e| match e {
            BootError::Revoked => AttestationError::Chain(BootError::Revoked),
            BootError::CertExpired => AttestationError::Chain(BootError::CertExpired),
            other => AttestationError::Chain(other),
        })?;

    // 3. разбор payload → отчёт
    let pv = Cbor::from_slice(&payload).map_err(|_| AttestationError::CborEncode)?;
    let report = report_from_cbor(&pv).ok_or(AttestationError::CborEncode)?;

    // 4. nonce binding (§13.17)
    if report.nonce != expect.nonce {
        return Err(AttestationError::NonceMismatch);
    }
    // 5. expiry: срок отчёта ≤ max_age (§13.19.2: ≤60 с)
    if expect.now_s < report.timestamp_s || expect.now_s - report.timestamp_s > expect.max_age_s {
        return Err(AttestationError::Expired);
    }
    // 6. PCR set
    for (idx, want) in expect.expected_pcrs {
        let got = report.pcrs.iter().find(|(i, _)| i == idx).map(|(_, v)| v);
        if got != Some(want) {
            return Err(AttestationError::PcrMismatch);
        }
    }
    // 7. policy hash
    if report.policy_hash != expect.policy_hash {
        return Err(AttestationError::PolicyHashMismatch);
    }
    // 8. HSM status
    if report.hsm_status != expect.hsm_status_required {
        return Err(AttestationError::HsmStatusBad);
    }
    // 9. model allowlist (BC-35)
    for m in &report.model_hashes {
        if m.len() != 64 {
            return Err(AttestationError::ModelNotAllowed);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(m);
        if !expect.model_allowlist.iter().any(|a| a == &arr) {
            return Err(AttestationError::ModelNotAllowed);
        }
    }
    // 10. минимальные версии прошивок
    for (name, minv) in expect.min_fw_versions {
        if let Some((_, vstr)) = report.fw_versions.iter().find(|(k, _)| k == name) {
            let v: u32 = vstr.parse().unwrap_or(0);
            if v < *minv {
                return Err(AttestationError::Expired);
            }
        } else {
            return Err(AttestationError::Expired);
        }
    }
    Ok(report)
}

pub fn report_from_cbor(v: &Cbor) -> Option<AttestationReport> {
    let mut fw = Vec::new();
    if let Cbor::Map(items) = v.get("fw_versions")? {
        for (k, val) in items {
            fw.push((k.as_text()?.to_owned(), val.as_text()?.to_owned()));
        }
    }
    let mut pcrs = Vec::new();
    if let Cbor::Map(items) = v.get("pcrs")? {
        for (k, val) in items {
            let idx = k.as_u64()? as u8;
            let b = val.as_bytes()?;
            if b.len() != 32 {
                return None;
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            pcrs.push((idx, a));
        }
    }
    let mut rb = Vec::new();
    if let Cbor::Map(items) = v.get("rollback_counters")? {
        for (k, val) in items {
            rb.push((k.as_text()?.to_owned(), val.as_u64()?));
        }
    }
    let models = v
        .get("model_hashes")?
        .as_array()?
        .iter()
        .map(|m| m.as_bytes().map(|b| b.to_vec()))
        .collect::<Option<Vec<_>>>()?;
    Some(AttestationReport {
        device_id: v.get("device_id")?.as_bytes()?.to_vec(),
        hw_rev: v.get("hw_rev")?.as_text()?.parse().ok()?,
        fw_versions: fw,
        pcrs,
        boot_mode: v.get("boot_mode")?.as_text()?.to_owned(),
        rollback_counters: rb,
        hsm_status: v.get("hsm_status")?.as_text()?.to_owned(),
        time_sync_quality: v.get("time_sync_quality")?.as_text()?.to_owned(),
        model_hashes: models,
        policy_hash: v.get("policy_hash")?.as_bytes()?.to_vec(),
        nonce: v.get("nonce")?.as_bytes()?.to_vec(),
        signature_alg: v.get("signature_alg")?.as_u64()? as u16,
        timestamp_s: v.get("timestamp_s")?.as_u64()?,
    })
}

/// Отпечаток отчёта для аудита (без чувствительных данных).
pub fn report_fingerprint(payload: &[u8]) -> [u8; 32] {
    streebog256(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakura_boot::cert::{key_id_of_pub, SignerCert, USAGE_FIRMWARE_SIGN};
    use sakura_hsm::soft::SoftHsm;
    use sakura_hsm::{KEY_TYPE_HYBRID_SIGN, KEY_CLASS_DEVICE_IDENTITY};
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    struct Fixture {
        root: HybridKeyPair,
        device_cert: SignerCert,
        anchor: TrustAnchor,
        hsm: SoftHsm,
        sid: SessionId,
        key_handle: KeyHandle,
        inputs: ReportInputs,
        nonce: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let root = HybridKeyPair::generate().unwrap();
        let anchor = TrustAnchor::new(root.public.clone(), Vec::new());

        // Ключ устройства генерируется ВНУТРИ SoftHsm (no key export) —
        // сертификат выпускается на публичную часть HSM-ключа (§22.18).
        let mut hsm = SoftHsm::new(b"hsm-pin").unwrap();
        let sid = hsm.open_session(b"hsm-pin").unwrap();
        let mut key_handle = 0u32;
        hsm.generate_key(sid, &[KEY_TYPE_HYBRID_SIGN, KEY_CLASS_DEVICE_IDENTITY], &mut key_handle)
            .unwrap();
        let hsm_pub_bytes = hsm.export_public_key(key_handle).unwrap();
        let hsm_pub = sakura_hybrid::HybridPublicKey::from_bytes(&hsm_pub_bytes).unwrap();
        let mut device_cert = SignerCert {
            subject_id: [0xD1; 16],
            signer_id: key_id_of_pub(&root.public),
            public: hsm_pub,
            key_usage: USAGE_FIRMWARE_SIGN, // leaf для подписи отчётов
            hw_rev_min: 1,
            not_before: 0,
            not_after: 4_000_000_000,
            signature: Vec::new(),
        };
        device_cert.signature = hybrid_sign(&root, &device_cert.tbs()).unwrap();

        let inputs = ReportInputs {
            fw_versions: vec![("pbl".into(), "3".into()), ("kernel".into(), "7".into())],
            pcrs: vec![(0, [1u8; 32]), (2, [2u8; 32])],
            boot_mode: "NORMAL".into(),
            rollback_counters: vec![("bootloader".into(), 3), ("kernel".into(), 7)],
            time_sync_quality: "LOCKED".into(),
            model_hashes: vec![],
            policy_hash: streebog256(b"policy-v1").to_vec(),
        };
        let nonce = vec![0x3F; 32];
        Fixture { root, device_cert, anchor, hsm, sid, key_handle, inputs, nonce }
    }

    #[test]
    fn attestation_full_cycle() {
        let mut f = fixture();
        let mut agent = AttestationAgent::new(vec![0xD1; 16], 2, f.key_handle);
        let mut sig_buf = [0u8; sakura_hybrid::HYBRID_SIG_LEN];
        let cose = agent
            .produce(&mut f.hsm, f.sid, &f.nonce, &f.inputs, &mut sig_buf)
            .unwrap();
        assert_eq!(agent.state, AttestationFsmState::ReturnReport);

        let now = time::unix_s();
        let expect = VerifyExpectations {
            nonce: &f.nonce,
            expected_pcrs: &[(0, [1u8; 32]), (2, [2u8; 32])],
            policy_hash: &f.inputs.policy_hash,
            hsm_status_required: "OK",
            model_allowlist: &[],
            now_s: now,
            max_age_s: REPORT_TTL_S,
            min_fw_versions: &[("kernel".to_owned(), 7)],
        };
        let report =
            verify_report(&cose, std::slice::from_ref(&f.device_cert), &f.anchor, &expect).unwrap();
        assert_eq!(report.boot_mode, "NORMAL");
        assert_eq!(report.nonce, f.nonce);
        assert_eq!(report.signature_alg, ALG_GOST_PLUS_MLDSA65 as u16);
        // подпись переменной длины (BC-19): 3373, не 96!
        let parsed = Cbor::from_slice(&cose).unwrap();
        let (_, _, sig) = parse_cose_sign1(&parsed).unwrap();
        assert_eq!(sig.len(), sakura_hybrid::HYBRID_SIG_LEN);
        assert_ne!(sig.len(), 96, "фиксированные 96 Б запрещены (BC-19)");
    }

    #[test]
    fn buffer_too_small_bc18() {
        let mut f = fixture();
        let mut agent = AttestationAgent::new(vec![0xD1; 16], 2, f.key_handle);
        let mut tiny = [0u8; 96]; // «универсальные 96 Б» — запрещены
        assert_eq!(
            agent.produce(&mut f.hsm, f.sid, &f.nonce, &f.inputs, &mut tiny),
            Err(AttestationError::BufferTooSmall)
        );
    }

    #[test]
    fn verifier_rejects_tampering() {
        let mut f = fixture();
        let mut agent = AttestationAgent::new(vec![0xD1; 16], 2, f.key_handle);
        let mut sig_buf = [0u8; sakura_hybrid::HYBRID_SIG_LEN];
        let cose = agent
            .produce(&mut f.hsm, f.sid, &f.nonce, &f.inputs, &mut sig_buf)
            .unwrap();
        let now = time::unix_s();
        let base = VerifyExpectations {
            nonce: &f.nonce,
            expected_pcrs: &[],
            policy_hash: &f.inputs.policy_hash,
            hsm_status_required: "OK",
            model_allowlist: &[],
            now_s: now,
            max_age_s: REPORT_TTL_S,
            min_fw_versions: &[],
        };
        // OK baseline
        verify_report(&cose, std::slice::from_ref(&f.device_cert), &f.anchor, &base).unwrap();
        // чужой nonce
        let bad_nonce = vec![0x00; 32];
        let e2 = VerifyExpectations { nonce: &bad_nonce, ..base.clone() };
        assert_eq!(
            verify_report(&cose, std::slice::from_ref(&f.device_cert), &f.anchor, &e2),
            Err(AttestationError::NonceMismatch)
        );
        // другой policy hash
        let bad_ph = streebog256(b"evil-policy").to_vec();
        let e3 = VerifyExpectations { policy_hash: &bad_ph, ..base.clone() };
        assert_eq!(
            verify_report(&cose, std::slice::from_ref(&f.device_cert), &f.anchor, &e3),
            Err(AttestationError::PolicyHashMismatch)
        );
        // просрочка (now + 61 с)
        let e4 = VerifyExpectations { now_s: now + REPORT_TTL_S + 1, ..base.clone() };
        assert_eq!(
            verify_report(&cose, std::slice::from_ref(&f.device_cert), &f.anchor, &e4),
            Err(AttestationError::Expired)
        );
        // PCR mismatch
        let e5 = VerifyExpectations { expected_pcrs: &[(0, [9u8; 32])], ..base.clone() };
        assert_eq!(
            verify_report(&cose, std::slice::from_ref(&f.device_cert), &f.anchor, &e5),
            Err(AttestationError::PcrMismatch)
        );
        // отозванный сертификат (CRL) → Chain(Revoked)
        let anchor_crl = TrustAnchor::new(
            f.root.public.clone(),
            vec![f.device_cert.subject_key_id()],
        );
        assert_eq!(
            verify_report(&cose, std::slice::from_ref(&f.device_cert), &anchor_crl, &base),
            Err(AttestationError::Chain(BootError::Revoked))
        );
        // битый байт подписи → Chain(GostSignatureInvalid или Pq…)
        let mut bad_cose = cose.clone();
        let n = bad_cose.len();
        bad_cose[n - 5] ^= 1;
        assert!(matches!(
            verify_report(&bad_cose, std::slice::from_ref(&f.device_cert), &f.anchor, &base),
            Err(AttestationError::Chain(_))
        ));
    }

}
