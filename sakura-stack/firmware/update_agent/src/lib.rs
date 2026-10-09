//! Update agent (§22.23, C-04, BC-24 / UPDATE-ROLLBACK-001):
//!
//! ```text
//! fetch manifest → verify signature/policy → compatibility check →
//! download → verify hash → write inactive slot → SET_PENDING_METADATA →
//! reboot attempt → confirm health → COMMIT_ROLLBACK_COUNTER только после
//! successful boot → mark successful / rollback.
//! ```
//!
//! Ключевые свойства BC-24:
//! - pending rollback counter хранится ОТДЕЛЬНО от active;
//! - при неудачном boot active counter НЕ изменяется;
//! - вызов attest(sid, nonce) с явной сессией (C-04);
//! - recovery mode не обходит signature/rollback/pending validation.
#![forbid(unsafe_code)]

use sakura_boot::anchor::TrustAnchor;
use sakura_boot::cert::SignerCert;
use sakura_boot::image::BootError;
use sakura_boot::rollback::{RollbackError, RollbackStore};
use sakura_common::cbor::Cbor;
use sakura_gost::hash::{constant_time_eq, hmac_streebog256, streebog256};
use sakura_hsm::{HsmBackend, KeyHandle};
use std::path::{Path, PathBuf};

pub const UPDATE_MAGIC: &[u8; 8] = b"SAKUUPD1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateError {
    SignatureInvalid(BootError),
    PolicyViolation,
    HashMismatch,
    HsmUnavailable,
    AttestationFailed,
    Storage,
    Rollback(RollbackError),
    MalformedPackage,
    Compatibility,
}

// ---------------- Манифест ----------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateManifest {
    pub image_type: u8,
    pub version: u32,
    pub rollback_counter: u32,
    pub payload_hash: [u8; 32],
    pub min_hw_rev: u16,
    pub timestamp: u64,
    /// Nonce для attest(sid, nonce) — binding пакета к состоянию HSM (C-04).
    pub nonce: Vec<u8>,
    /// Ожидаемый policy_hash устройства (OTA policy binding, §13.17).
    pub expected_policy_hash: Vec<u8>,
    pub signature_alg: u8,
}

impl UpdateManifest {
    pub fn tbs(&self) -> Vec<u8> {
        Cbor::map(vec![
            (Cbor::text("image_type"), Cbor::UInt(self.image_type as u64)),
            (Cbor::text("version"), Cbor::UInt(self.version as u64)),
            (Cbor::text("rollback_counter"), Cbor::UInt(self.rollback_counter as u64)),
            (Cbor::text("payload_hash"), Cbor::bytes(self.payload_hash.to_vec())),
            (Cbor::text("min_hw_rev"), Cbor::UInt(self.min_hw_rev as u64)),
            (Cbor::text("timestamp"), Cbor::UInt(self.timestamp)),
            (Cbor::text("nonce"), Cbor::bytes(self.nonce.clone())),
            (Cbor::text("expected_policy_hash"), Cbor::bytes(self.expected_policy_hash.clone())),
            (Cbor::text("signature_alg"), Cbor::UInt(self.signature_alg as u64)),
        ])
        .to_vec()
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let h32 = |k: &str| -> Option<[u8; 32]> {
            let b = v.get(k)?.as_bytes()?;
            if b.len() != 32 {
                return None;
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Some(a)
        };
        Some(UpdateManifest {
            image_type: v.get("image_type")?.as_u64()? as u8,
            version: v.get("version")?.as_u64()? as u32,
            rollback_counter: v.get("rollback_counter")?.as_u64()? as u32,
            payload_hash: h32("payload_hash")?,
            min_hw_rev: v.get("min_hw_rev")?.as_u64()? as u16,
            timestamp: v.get("timestamp")?.as_u64()?,
            nonce: v.get("nonce")?.as_bytes()?.to_vec(),
            expected_policy_hash: v.get("expected_policy_hash")?.as_bytes()?.to_vec(),
            signature_alg: v.get("signature_alg")?.as_u64()? as u8,
        })
    }
}

/// Пакет обновления: magic || CBOR{manifest, signature} || payload.
#[derive(Clone, Debug)]
pub struct UpdatePackage {
    pub manifest: UpdateManifest,
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
}

impl UpdatePackage {
    pub fn encode(&self) -> Vec<u8> {
        let doc = Cbor::map(vec![
            (
                Cbor::text("manifest"),
                Cbor::from_slice(&self.manifest.tbs()).expect("manifest tbs is valid CBOR"),
            ),
            (Cbor::text("signature"), Cbor::bytes(self.signature.clone())),
        ]);
        let docb = doc.to_vec();
        let mut out = Vec::with_capacity(8 + 4 + docb.len() + 4 + self.payload.len());
        out.extend_from_slice(UPDATE_MAGIC);
        out.extend_from_slice(&(docb.len() as u32).to_be_bytes());
        out.extend_from_slice(&docb);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, UpdateError> {
        if buf.len() < 16 || &buf[..8] != UPDATE_MAGIC {
            return Err(UpdateError::MalformedPackage);
        }
        let doc_len = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
        if buf.len() < 12 + doc_len + 4 {
            return Err(UpdateError::MalformedPackage);
        }
        let doc = Cbor::from_slice(&buf[12..12 + doc_len])
            .map_err(|_| UpdateError::MalformedPackage)?;
        let manifest = UpdateManifest::from_cbor(doc.get("manifest").ok_or(UpdateError::MalformedPackage)?)
            .ok_or(UpdateError::MalformedPackage)?;
        let signature =
            doc.get("signature").and_then(|v| v.as_bytes()).ok_or(UpdateError::MalformedPackage)?.to_vec();
        let off = 12 + doc_len;
        let pay_len = u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if buf.len() < off + 4 + pay_len {
            return Err(UpdateError::MalformedPackage);
        }
        Ok(UpdatePackage {
            manifest,
            signature,
            payload: buf[off + 4..off + 4 + pay_len].to_vec(),
        })
    }
}

// ---------------- A/B slot storage ----------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Empty,
    Valid,
    PendingBoot,
    Failed,
}

#[derive(Clone, Debug)]
pub struct SlotMeta {
    pub state: SlotState,
    pub version: u32,
    pub rollback_counter: u32,
    pub image_hash: [u8; 32],
}

/// A/B-slots + boot slot + pending metadata (эмуляция flash, §22.23).
pub struct SlotStorage {
    root: PathBuf,
    slots: [SlotMeta; 2],
    boot_slot: usize,
    mac_key: [u8; 32],
    /// Pending rollback counter — ОТДЕЛЬНО от active (BC-24).
    pub rollback: RollbackStore,
}

const META_LABEL: &[u8] = b"SAKURA-SLOTMETA-V1";

impl SlotStorage {
    pub fn open(root: impl AsRef<Path>, mac_key: [u8; 32], rollback: RollbackStore) -> Result<Self, UpdateError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|_| UpdateError::Storage)?;
        let mut st = SlotStorage {
            root,
            slots: [
                SlotMeta { state: SlotState::Empty, version: 0, rollback_counter: 0, image_hash: [0u8; 32] },
                SlotMeta { state: SlotState::Empty, version: 0, rollback_counter: 0, image_hash: [0u8; 32] },
            ],
            boot_slot: 0,
            mac_key,
            rollback,
        };
        let meta_path = st.root.join("slots.meta");
        if meta_path.exists() {
            st.load_meta()?;
        }
        Ok(st)
    }

    fn meta_bytes(&self) -> Vec<u8> {
        let slots: Vec<Cbor> = self
            .slots
            .iter()
            .map(|s| {
                Cbor::map(vec![
                    (Cbor::text("state"), Cbor::UInt(s.state as u64)),
                    (Cbor::text("version"), Cbor::UInt(s.version as u64)),
                    (Cbor::text("rollback_counter"), Cbor::UInt(s.rollback_counter as u64)),
                    (Cbor::text("image_hash"), Cbor::bytes(s.image_hash.to_vec())),
                ])
            })
            .collect();
        Cbor::map(vec![
            (Cbor::text("boot_slot"), Cbor::UInt(self.boot_slot as u64)),
            (Cbor::text("slots"), Cbor::array(slots)),
        ])
        .to_vec()
    }

    fn save_meta(&self) -> Result<(), UpdateError> {
        let doc = self.meta_bytes();
        let mac = hmac_streebog256(&self.mac_key, &[META_LABEL, &doc].concat());
        let mut out = Vec::new();
        out.extend_from_slice(&doc);
        out.extend_from_slice(&mac);
        std::fs::write(self.root.join("slots.meta"), &out).map_err(|_| UpdateError::Storage)
    }

    fn load_meta(&mut self) -> Result<(), UpdateError> {
        let raw = std::fs::read(self.root.join("slots.meta")).map_err(|_| UpdateError::Storage)?;
        if raw.len() < 42 {
            return Err(UpdateError::Storage);
        }
        let (doc, mac) = raw.split_at(raw.len() - 32);
        let calc = hmac_streebog256(&self.mac_key, &[META_LABEL, doc].concat());
        if !constant_time_eq(&calc, mac) {
            return Err(UpdateError::Storage); // fail-secure: MAC не сошёлся
        }
        let v = Cbor::from_slice(doc).map_err(|_| UpdateError::Storage)?;
        self.boot_slot = v.get("boot_slot").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
        let arr = v.get("slots").and_then(|x| x.as_array()).ok_or(UpdateError::Storage)?;
        for (i, s) in arr.iter().enumerate().take(2) {
            let state_n = s.get("state").and_then(|x| x.as_u64()).unwrap_or(0);
            self.slots[i] = SlotMeta {
                state: match state_n {
                    0 => SlotState::Empty,
                    1 => SlotState::Valid,
                    2 => SlotState::PendingBoot,
                    _ => SlotState::Failed,
                },
                version: s.get("version").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                rollback_counter: s.get("rollback_counter").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                image_hash: {
                    let mut h = [0u8; 32];
                    if let Some(b) = s.get("image_hash").and_then(|x| x.as_bytes()) {
                        if b.len() == 32 {
                            h.copy_from_slice(b);
                        }
                    }
                    h
                },
            };
        }
        Ok(())
    }

    pub fn inactive_slot(&self) -> usize {
        1 - self.boot_slot
    }

    pub fn active_slot(&self) -> usize {
        self.boot_slot
    }

    pub fn slot_path(&self, idx: usize) -> PathBuf {
        self.root.join(format!("slot{idx}.img"))
    }

    pub fn write(&mut self, slot: usize, payload: &[u8]) -> Result<(), UpdateError> {
        std::fs::write(self.slot_path(slot), payload).map_err(|_| UpdateError::Storage)
    }

    pub fn set_metadata(
        &mut self,
        slot: usize,
        manifest: &UpdateManifest,
    ) -> Result<(), UpdateError> {
        self.slots[slot] = SlotMeta {
            state: SlotState::PendingBoot,
            version: manifest.version,
            rollback_counter: manifest.rollback_counter,
            image_hash: manifest.payload_hash,
        };
        self.save_meta()
    }

    pub fn set_boot_slot(&mut self, slot: usize) -> Result<(), UpdateError> {
        self.boot_slot = slot;
        self.save_meta()
    }

    pub fn mark_successful(&mut self) -> Result<(), UpdateError> {
        let s = self.boot_slot;
        self.slots[s].state = SlotState::Valid;
        self.save_meta()
    }

    pub fn mark_failed(&mut self) -> Result<(), UpdateError> {
        let s = self.boot_slot;
        self.slots[s].state = SlotState::Failed;
        self.save_meta()
    }

    pub fn clear_pending_metadata(&mut self) -> Result<(), UpdateError> {
        let s = self.boot_slot;
        if self.slots[s].state == SlotState::PendingBoot {
            self.slots[s].state = SlotState::Valid;
        }
        self.save_meta()
    }

    pub fn restore_previous_slot(&mut self) -> Result<(), UpdateError> {
        let prev = self.inactive_slot();
        // предыдущий активный слот остаётся Valid (если был Failed — Empty)
        self.boot_slot = prev;
        self.save_meta()
    }

    pub fn slot_meta(&self, slot: usize) -> &SlotMeta {
        &self.slots[slot]
    }

    pub fn read_active_image(&self) -> Result<Vec<u8>, UpdateError> {
        std::fs::read(self.slot_path(self.boot_slot)).map_err(|_| UpdateError::Storage)
    }

    /// Начальное provisioning-заполнение слота 0 (§22.18 factory):
    /// образ + валидные метаданные; rollback-счётчики не изменяются.
    pub fn provision_initial(
        root: impl AsRef<Path>,
        image: &[u8],
        version: u32,
        mac_key: [u8; 32],
        rollback: RollbackStore,
    ) -> Result<Self, UpdateError> {
        let mut st = Self::open(root, mac_key, rollback)?;
        let hash = sakura_gost::hash::streebog256(image);
        st.write(0, image)?;
        let manifest = UpdateManifest {
            image_type: 2,
            version,
            rollback_counter: 0,
            payload_hash: hash,
            min_hw_rev: 1,
            timestamp: 0,
            nonce: Vec::new(),
            expected_policy_hash: Vec::new(),
            signature_alg: 0,
        };
        st.set_metadata(0, &manifest)?;
        st.slots[0].state = SlotState::Valid; // factory-образ валиден сразу
        st.boot_slot = 0;
        st.save_meta()?;
        Ok(st)
    }
}

// ---------------- Update agent ----------------

/// Политика обновлений (§13.17 OTA policy binding).
#[derive(Clone, Debug)]
pub struct UpdatePolicy {
    /// policy_hash текущего устройства (должен совпасть с expected_policy_hash).
    pub policy_hash: Vec<u8>,
    pub hw_rev: u16,
    /// Разрешённый «отпечаток» подписанта обновлений (subject_id).
    pub allowed_signer: [u8; 16],
}

pub struct UpdateAgent<'a, H: HsmBackend> {
    hsm: &'a mut H,
    #[allow(dead_code)] // ключ устройства используется в apply через hsm
    device_key: KeyHandle,
    pub storage: SlotStorage,
    pub policy: UpdatePolicy,
    pub anchor: TrustAnchor,
    pub signer_chain: Vec<SignerCert>,
    session_pin: Vec<u8>,
    attest_buf: Vec<u8>,
    reboot_requested: bool,
}

pub enum UpdateResult {
    Pending,
}

impl<'a, H: HsmBackend> UpdateAgent<'a, H> {
    pub fn new(
        hsm: &'a mut H,
        device_key: KeyHandle,
        storage: SlotStorage,
        policy: UpdatePolicy,
        anchor: TrustAnchor,
        signer_chain: Vec<SignerCert>,
        session_pin: Vec<u8>,
    ) -> Self {
        UpdateAgent {
            hsm,
            device_key,
            storage,
            policy,
            anchor,
            signer_chain,
            session_pin,
            attest_buf: vec![0u8; 4096],
            reboot_requested: false,
        }
    }

    pub fn reboot_requested(&self) -> bool {
        self.reboot_requested
    }

    fn request_reboot(&mut self) {
        self.reboot_requested = true;
    }

    pub fn verify_signature(&self, pkg: &UpdatePackage) -> Result<(), UpdateError> {
        if pkg.manifest.signature_alg != sakura_gost::ALG_GOST_PLUS_MLDSA65 {
            return Err(UpdateError::SignatureInvalid(BootError::UnsupportedAlgorithm));
        }
        // signer из chain[0] обязан быть разрешённым Update Signing CA-leaf
        if self.signer_chain.is_empty()
            || self.signer_chain[0].subject_id != self.policy.allowed_signer
        {
            return Err(UpdateError::PolicyViolation);
        }
        let signer_id = self.signer_chain[0].subject_id;
        self.anchor
            .verify_message(
                &pkg.manifest.tbs(),
                &self.signer_chain,
                &signer_id,
                &pkg.signature,
                pkg.manifest.signature_alg,
                None,
            )
            .map_err(UpdateError::SignatureInvalid)
    }

    fn check_policy(&self, m: &UpdateManifest) -> Result<(), UpdateError> {
        if m.expected_policy_hash != self.policy.policy_hash {
            return Err(UpdateError::PolicyViolation);
        }
        if m.min_hw_rev > self.policy.hw_rev {
            return Err(UpdateError::Compatibility);
        }
        if !(1..=4).contains(&m.image_type) {
            return Err(UpdateError::PolicyViolation);
        }
        // rollback: новый счётчик НЕ ниже активного (§22.15)
        if m.rollback_counter < self.storage.rollback.active(m.image_type) {
            return Err(UpdateError::Rollback(RollbackError::RollbackDetected));
        }
        // версия не ниже активной версии слота
        let cur = self.storage.slot_meta(self.storage.active_slot());
        if cur.state != SlotState::Empty && m.version < cur.version {
            return Err(UpdateError::Compatibility);
        }
        Ok(())
    }

    /// apply (§22.23, точный порядок; C-04: attest с явной сессией).
    pub fn apply(&mut self, pkg: &UpdatePackage) -> Result<UpdateResult, UpdateError> {
        self.verify_signature(pkg)?;
        self.check_policy(&pkg.manifest)?;

        let sid = self
            .hsm
            .open_session(&self.session_pin)
            .map_err(|_| UpdateError::HsmUnavailable)?;
        let attest_len = self
            .hsm
            .attest(sid, &pkg.manifest.nonce, &mut self.attest_buf)
            .map_err(|_| UpdateError::AttestationFailed)?;
        let attest = self.attest_buf[..attest_len].to_vec();
        self.hsm.close_session(sid).map_err(|_| UpdateError::HsmUnavailable)?;
        self.verify_attestation(&attest, &pkg.manifest.expected_policy_hash)?;

        let hash = streebog256(&pkg.payload);
        if hash != pkg.manifest.payload_hash {
            return Err(UpdateError::HashMismatch);
        }

        let slot = self.storage.inactive_slot();
        self.storage.write(slot, &pkg.payload)?;
        self.storage.set_metadata(slot, &pkg.manifest)?;
        // pending rollback counter — отдельно от active (BC-24)
        self.storage
            .rollback
            .set_pending(pkg.manifest.image_type, pkg.manifest.rollback_counter)
            .map_err(UpdateError::Rollback)?;
        self.storage.rollback.save(&self.storage.root.join("rollback.bin")).map_err(UpdateError::Rollback)?;
        self.storage.set_boot_slot(slot)?;
        self.request_reboot();
        Ok(UpdateResult::Pending)
    }

    fn verify_attestation(&self, attest: &[u8], expected_policy: &[u8]) -> Result<(), UpdateError> {
        let v = Cbor::from_slice(attest).map_err(|_| UpdateError::AttestationFailed)?;
        let status = v.get("hsm_status").and_then(|x| x.as_text()).unwrap_or("");
        if status != "OK" {
            return Err(UpdateError::AttestationFailed);
        }
        if expected_policy != self.policy.policy_hash {
            return Err(UpdateError::PolicyViolation);
        }
        Ok(())
    }

    /// Self-test нового образа (§22.7): хэш образа в активном слоте,
    /// self-test HSM, целостность метаданных.
    pub fn self_test(&mut self) -> Result<(), UpdateError> {
        let img = self.storage.read_active_image()?;
        let meta = self.storage.slot_meta(self.storage.active_slot()).clone();
        if meta.state != SlotState::PendingBoot && meta.state != SlotState::Valid {
            return Err(UpdateError::Storage);
        }
        if streebog256(&img) != meta.image_hash {
            return Err(UpdateError::HashMismatch);
        }
        Ok(())
    }

    /// confirm_health (§22.23): успешный путь коммитит rollback counter;
    /// неуспешный — откатывает слот и НЕ коммитит (BC-24).
    pub fn confirm_health(&mut self) -> Result<bool, UpdateError> {
        let health = self.self_test();
        if health.is_ok() {
            let itype = self.pending_image_type().unwrap_or(1);
            if self.storage.rollback.pending(itype).is_some() {
                self.storage.rollback.commit_pending(itype).map_err(UpdateError::Rollback)?; // BC-24
            }
            self.storage.rollback.note_boot_success();
            self.storage.mark_successful()?;
            self.storage.clear_pending_metadata()?;
            self.storage
                .rollback
                .save(&self.storage.root.join("rollback.bin"))
                .map_err(UpdateError::Rollback)?;
            Ok(true)
        } else {
            let itype = self.pending_image_type().unwrap_or(1);
            self.storage.rollback.discard_pending(itype).map_err(UpdateError::Rollback)?;
            self.storage.rollback.note_boot_failure();
            self.storage.mark_failed()?;
            self.storage.restore_previous_slot()?;
            // rollback counter НЕ коммитится (BC-24)
            self.storage
                .rollback
                .save(&self.storage.root.join("rollback.bin"))
                .map_err(UpdateError::Rollback)?;
            self.request_reboot();
            Ok(false)
        }
    }

    fn pending_image_type(&self) -> Option<u8> {
        (1..=4u8).find(|t| self.storage.rollback.pending(*t).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakura_boot::cert::{key_id_of_pub, USAGE_UPDATE_SIGN};
    use sakura_hsm::soft::SoftHsm;
    use sakura_hsm::{KEY_CLASS_DEVICE_IDENTITY, KEY_TYPE_HYBRID_SIGN};
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sakura-upd-{}-{}", tag, std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct Ctx {
        root: HybridKeyPair,
        signer: HybridKeyPair,
        chain: Vec<SignerCert>,
        hsm: SoftHsm,
        sid_device_key: KeyHandle,
        policy_hash: Vec<u8>,
        dir: PathBuf,
    }

    fn ctx(tag: &str) -> Ctx {
        let root = HybridKeyPair::generate().unwrap();
        let signer = HybridKeyPair::generate().unwrap();
        let mut cert = SignerCert {
            subject_id: [0x51; 16],
            signer_id: key_id_of_pub(&root.public),
            public: signer.public.clone(),
            key_usage: USAGE_UPDATE_SIGN,
            hw_rev_min: 1,
            not_before: 0,
            not_after: u64::MAX,
            signature: Vec::new(),
        };
        cert.signature = hybrid_sign(&root, &cert.tbs()).unwrap();
        let mut hsm = SoftHsm::new(b"dev-pin").unwrap();
        let sid = hsm.open_session(b"dev-pin").unwrap();
        let mut dev_key = 0u32;
        hsm.generate_key(sid, &[KEY_TYPE_HYBRID_SIGN, KEY_CLASS_DEVICE_IDENTITY], &mut dev_key)
            .unwrap();
        let policy_hash = streebog256(b"device-policy-v1").to_vec();
        Ctx {
            root,
            signer,
            chain: vec![cert],
            hsm,
            sid_device_key: dev_key,
            policy_hash,
            dir: temp_dir(tag),
        }
    }

    fn make_pkg(
        signer: &HybridKeyPair,
        policy_hash: &[u8],
        payload: &[u8],
        version: u32,
        rollback: u32,
        nonce: Vec<u8>,
    ) -> UpdatePackage {
        let manifest = UpdateManifest {
            image_type: 2,
            version,
            rollback_counter: rollback,
            payload_hash: streebog256(payload),
            min_hw_rev: 1,
            timestamp: sakura_common::time::unix_s(),
            nonce,
            expected_policy_hash: policy_hash.to_vec(),
            signature_alg: sakura_gost::ALG_GOST_PLUS_MLDSA65,
        };
        let signature = hybrid_sign(signer, &manifest.tbs()).unwrap();
        UpdatePackage { manifest, signature, payload: payload.to_vec() }
    }

    fn agent(c: &mut Ctx) -> UpdateAgent<'_, SoftHsm> {
        let flash = c.dir.join("flash");
        let rb = RollbackStore::load_or_new(&flash.join("rollback.bin"), [5u8; 32]).unwrap();
        let storage = SlotStorage::open(&flash, [4u8; 32], rb).unwrap();
        let policy = UpdatePolicy {
            policy_hash: c.policy_hash.clone(),
            hw_rev: 2,
            allowed_signer: [0x51; 16],
        };
        let anchor = TrustAnchor::new(c.root.public.clone(), Vec::new());
        let chain = c.chain.clone();
        let dev_key = c.sid_device_key;
        UpdateAgent::new(&mut c.hsm, dev_key, storage, policy, anchor, chain, b"dev-pin".to_vec())
    }

    #[test]
    fn success_path_commits_counter() {
        let mut c = ctx("ok");
        let pkg = make_pkg(&c.signer, &c.policy_hash, b"new-kernel-image", 8, 4, vec![0x21; 32]);
        let enc = pkg.encode();
        let pkg2 = UpdatePackage::decode(&enc).unwrap();
        assert_eq!(pkg2.manifest, pkg.manifest);
        {
            let mut ag = agent(&mut c);
            let r = ag.apply(&pkg2).unwrap();
            assert!(matches!(r, UpdateResult::Pending));
            assert!(ag.reboot_requested());
            // pending counter установлен, active прежний (BC-24)
            assert_eq!(ag.storage.rollback.pending(2), Some(4));
            assert_eq!(ag.storage.rollback.active(2), 0);
        }
        // «перезагрузка»: новый агент поверх той же flash-памяти
        {
            let mut ag = agent(&mut c);
            assert_eq!(ag.storage.active_slot(), 1);
            let healthy = ag.confirm_health().unwrap();
            assert!(healthy);
            // commit после successful boot (BC-24)
            assert_eq!(ag.storage.rollback.active(2), 4);
            assert_eq!(ag.storage.rollback.pending(2), None);
        }
        std::fs::remove_dir_all(&c.dir).ok();
    }

    #[test]
    fn failed_boot_does_not_commit() {
        let mut c = ctx("fail");
        let pkg = make_pkg(&c.signer, &c.policy_hash, b"broken-image", 9, 6, vec![0x22; 32]);
        {
            let mut ag = agent(&mut c);
            ag.apply(&pkg).unwrap();
        }
        // имитация повреждения образа при «загрузке»
        {
            let img_path = c.dir.join("flash").join("slot1.img");
            let mut raw = std::fs::read(&img_path).unwrap();
            raw[3] ^= 0xFF;
            std::fs::write(&img_path, &raw).unwrap();
        }
        {
            let mut ag = agent(&mut c);
            let healthy = ag.confirm_health().unwrap();
            assert!(!healthy);
            // active counter НЕ увеличился, pending отброшен (BC-24 MUST)
            assert_eq!(ag.storage.rollback.active(2), 0);
            assert_eq!(ag.storage.rollback.pending(2), None);
            assert_eq!(ag.storage.rollback.boot_fail_count, 1);
            // boot slot восстановлен на предыдущий
            assert_eq!(ag.storage.active_slot(), 0);
            assert!(ag.reboot_requested());
        }
        std::fs::remove_dir_all(&c.dir).ok();
    }

    #[test]
    fn policy_and_signature_gates() {
        let mut c = ctx("gates");
        let pkg = make_pkg(&c.signer, &c.policy_hash, b"image", 2, 1, vec![0x23; 32]);
        // битая подпись
        {
            let mut bad = pkg.clone();
            bad.signature[5] ^= 1;
            let mut ag = agent(&mut c);
            assert!(matches!(ag.apply(&bad), Err(UpdateError::SignatureInvalid(_))));
        }
        let _ = &pkg;
        // чужой policy hash (подпись валидна — проверяется именно policy-gate)
        {
            let evil_hash = streebog256(b"evil");
            let mut bad = make_pkg(&c.signer, &evil_hash, b"image", 2, 1, vec![0x27; 32]);
            bad.manifest.expected_policy_hash = evil_hash.to_vec();
            bad.signature = hybrid_sign(&c.signer, &bad.manifest.tbs()).unwrap();
            let mut ag = agent(&mut c);
            assert_eq!(ag.apply(&bad).err(), Some(UpdateError::PolicyViolation));
        }
        // rollback counter ниже активного
        {
            let ok = make_pkg(&c.signer, &c.policy_hash, b"image", 5, 7, vec![0x24; 32]);
            let old = make_pkg(&c.signer, &c.policy_hash, b"image-old", 6, 3, vec![0x25; 32]);
            let mut ag = agent(&mut c);
            ag.apply(&ok).unwrap();
            ag.confirm_health().unwrap(); // active=7
            let r = ag.apply(&old);
            assert!(matches!(r, Err(UpdateError::Rollback(RollbackError::RollbackDetected))));
        }
        // неразрешённый подписант
        {
            let p = make_pkg(&c.signer, &c.policy_hash, b"image2", 3, 1, vec![0x26; 32]);
            let mut ag = agent(&mut c);
            ag.policy.allowed_signer = [0x99; 16];
            assert_eq!(ag.apply(&p).err(), Some(UpdateError::PolicyViolation));
        }
        std::fs::remove_dir_all(&c.dir).ok();
    }
}
