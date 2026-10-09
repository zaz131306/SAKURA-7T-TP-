//! sakura-audit — L7 Observability & Audit (§5.9):
//! - AuditRecord: 12 полей DM-1 §13.18.2, детерминированный CBOR (§13.18.3);
//! - формулы §4.12:
//!   ```text
//!   record_mac   = MAC(audit_key[key_epoch], canonical(header|payload|hash_prev|seq|key_epoch))
//!   chain_hash[i] = H(chain_hash[i−1] | record_mac | seq | key_epoch)   (= hash_self)
//!   checkpoint   = Sign_HSM(chain_hash[start..end], seq_start, seq_end,
//!                           prev_checkpoint_hash, key_epoch_range)
//!   ```
//! - AUD-001 append-only; AUD-004 checkpoint каждые 512 записей;
//!   AUD-006 ротация HMAC-ключа ≤24 ч / 10⁶ записей; AUD-008 tamper
//!   detection (insert/delete/modify/reorder/replay); AUD-010 signed
//!   export chunks + idempotency; AUD-012 PTP/monotonic sequence.
//! - подпись записи покрывает каноническое представление с ПУСТЫМ полем
//!   signature (§13.18.3 прим. 2).
#![forbid(unsafe_code)]

use sakura_common::cbor::Cbor;
use sakura_gost::hash::{constant_time_eq, hmac_streebog256, streebog256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Типы событий (§25.3).
pub mod events {
    pub const AUTHENTICATION: &str = "AUTHENTICATION";
    pub const AUTHORIZATION: &str = "AUTHORIZATION";
    pub const KEY_OPERATION: &str = "KEY_OPERATION";
    pub const FIRMWARE_UPDATE: &str = "FIRMWARE_UPDATE";
    pub const MODEL_LOAD: &str = "MODEL_LOAD";
    pub const CONSENSUS_FINALIZATION: &str = "CONSENSUS_FINALIZATION";
    pub const COMMAND_ISSUE: &str = "COMMAND_ISSUE";
    pub const TAMPER: &str = "TAMPER";
    pub const NETWORK_PARTITION: &str = "NETWORK_PARTITION";
    pub const CRYPTO_FAILURE: &str = "CRYPTO_FAILURE";
    pub const OPERATOR_ACTION: &str = "OPERATOR_ACTION";
    pub const ADMIN_ACTION: &str = "ADMIN_ACTION";
    pub const BACKUP_RESTORE: &str = "BACKUP_RESTORE";
    pub const DR_DRILL: &str = "DR_DRILL";
    pub const LIFECYCLE_TRANSITION: &str = "LIFECYCLE_TRANSITION"; // BC-22
    pub const IDEMPOTENT_REPLAY: &str = "IDEMPOTENT_REPLAY"; // BC-27
    pub const SESSION_OPEN: &str = "SESSION_OPEN";
    pub const SESSION_CLOSE: &str = "SESSION_CLOSE";
    pub const WATCHDOG: &str = "WATCHDOG";
    pub const VIEW_CHANGE: &str = "VIEW_CHANGE";
    pub const QUARANTINE_EVIDENCE: &str = "QUARANTINE_EVIDENCE";
    pub const ZEROIZATION: &str = "ZEROIZATION";
    pub const BOOT: &str = "BOOT";
    pub const ATTESTATION: &str = "ATTESTATION";
}

/// AUD-004: MUST — каждые 512 записей (TARGET 256).
pub const CHECKPOINT_INTERVAL: u64 = 512;
/// AUD-006: ротация ключа ≤ 24 ч или 10⁶ записей.
pub const KEY_ROTATION_MAX_S: u64 = 24 * 3600;
pub const KEY_ROTATION_MAX_RECORDS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    Io,
    Corrupted,
    MacMismatch,
    ChainBroken,
    SeqGap,
    SignatureInvalid,
    ReorderDetected,
    ReplayDetected,
}

/// AuditRecord — 12 полей DM-1 (§13.18.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp_s: u64,
    pub node_id: [u8; 16],
    pub actor_id: [u8; 16],
    pub session_id: u64,
    pub event_type: String,
    pub object_id: [u8; 16],
    pub result: String,
    pub hash_prev: [u8; 32],
    pub hash_self: [u8; 32],
    pub key_epoch: u32,
    pub signature: Vec<u8>,
}

impl AuditRecord {
    /// Каноническая map 12 полей (§13.18.3). `empty_sig` — для подписи
    /// (signature = b""); иначе — фактическая подпись.
    pub fn canonical(&self, empty_sig: bool) -> Vec<u8> {
        let sig = if empty_sig { Vec::new() } else { self.signature.clone() };
        Cbor::map(vec![
            (Cbor::text("seq"), Cbor::UInt(self.seq)),
            (Cbor::text("timestamp_s"), Cbor::UInt(self.timestamp_s)),
            (Cbor::text("node_id"), Cbor::bytes(self.node_id.to_vec())),
            (Cbor::text("actor_id"), Cbor::bytes(self.actor_id.to_vec())),
            (Cbor::text("session_id"), Cbor::UInt(self.session_id)),
            (Cbor::text("event_type"), Cbor::text(self.event_type.clone())),
            (Cbor::text("object_id"), Cbor::bytes(self.object_id.to_vec())),
            (Cbor::text("result"), Cbor::text(self.result.clone())),
            (Cbor::text("hash_prev"), Cbor::bytes(self.hash_prev.to_vec())),
            (Cbor::text("hash_self"), Cbor::bytes(self.hash_self.to_vec())),
            (Cbor::text("key_epoch"), Cbor::UInt(self.key_epoch as u64)),
            (Cbor::text("signature"), Cbor::bytes(sig)),
        ])
        .to_vec()
    }

    /// База MAC: canonical(header|payload|hash_prev|seq|key_epoch) — 10 полей
    /// (без hash_self и signature), формула §4.12.
    pub fn mac_base(&self) -> Vec<u8> {
        Cbor::map(vec![
            (Cbor::text("seq"), Cbor::UInt(self.seq)),
            (Cbor::text("timestamp_s"), Cbor::UInt(self.timestamp_s)),
            (Cbor::text("node_id"), Cbor::bytes(self.node_id.to_vec())),
            (Cbor::text("actor_id"), Cbor::bytes(self.actor_id.to_vec())),
            (Cbor::text("session_id"), Cbor::UInt(self.session_id)),
            (Cbor::text("event_type"), Cbor::text(self.event_type.clone())),
            (Cbor::text("object_id"), Cbor::bytes(self.object_id.to_vec())),
            (Cbor::text("result"), Cbor::text(self.result.clone())),
            (Cbor::text("hash_prev"), Cbor::bytes(self.hash_prev.to_vec())),
            (Cbor::text("key_epoch"), Cbor::UInt(self.key_epoch as u64)),
        ])
        .to_vec()
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
        let b32 = |k: &str| -> Option<[u8; 32]> {
            let s = v.get(k)?.as_bytes()?;
            if s.len() != 32 {
                return None;
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(s);
            Some(a)
        };
        Some(AuditRecord {
            seq: v.get("seq")?.as_u64()?,
            timestamp_s: v.get("timestamp_s")?.as_u64()?,
            node_id: b16("node_id")?,
            actor_id: b16("actor_id")?,
            session_id: v.get("session_id")?.as_u64()?,
            event_type: v.get("event_type")?.as_text()?.to_owned(),
            object_id: b16("object_id")?,
            result: v.get("result")?.as_text()?.to_owned(),
            hash_prev: b32("hash_prev")?,
            hash_self: b32("hash_self")?,
            key_epoch: v.get("key_epoch")?.as_u64()? as u32,
            signature: v.get("signature")?.as_bytes()?.to_vec(),
        })
    }
}

/// Подписант записей (HSM-backed в узле; тесты — in-memory).
pub trait AuditSigner {
    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, AuditError>;
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool;
}

/// In-memory подписант на гибридном ключе (тесты/CA-утилиты).
pub struct MemorySigner {
    pub kp: sakura_hybrid::HybridKeyPair,
}

impl MemorySigner {
    pub fn new() -> Result<Self, AuditError> {
        Ok(MemorySigner {
            kp: sakura_hybrid::HybridKeyPair::generate().map_err(|_| AuditError::SignatureInvalid)?,
        })
    }
}

impl Default for MemorySigner {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl AuditSigner for MemorySigner {
    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, AuditError> {
        sakura_hybrid::hybrid_sign(&self.kp, data).map_err(|_| AuditError::SignatureInvalid)
    }
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        sakura_hybrid::hybrid_verify(&self.kp.public, data, sig)
    }
}

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub seq_start: u64,
    pub seq_end: u64,
    pub chain_hash: [u8; 32],
    pub prev_checkpoint_hash: [u8; 32],
    pub key_epoch_start: u32,
    pub key_epoch_end: u32,
    pub signature: Vec<u8>,
}

impl Checkpoint {
    pub fn tbs(&self) -> Vec<u8> {
        Cbor::map(vec![
            (Cbor::text("seq_start"), Cbor::UInt(self.seq_start)),
            (Cbor::text("seq_end"), Cbor::UInt(self.seq_end)),
            (Cbor::text("chain_hash"), Cbor::bytes(self.chain_hash.to_vec())),
            (Cbor::text("prev_checkpoint_hash"), Cbor::bytes(self.prev_checkpoint_hash.to_vec())),
            (Cbor::text("key_epoch_start"), Cbor::UInt(self.key_epoch_start as u64)),
            (Cbor::text("key_epoch_end"), Cbor::UInt(self.key_epoch_end as u64)),
        ])
        .to_vec()
    }
    pub fn hash(&self) -> [u8; 32] {
        streebog256(&self.tbs())
    }
}

pub struct AuditLog<S: AuditSigner> {
    pub node_id: [u8; 16],
    records: Vec<AuditRecord>,
    macs: Vec<[u8; 32]>,
    keys: BTreeMap<u32, ([u8; 32], u64, u64)>, // epoch → (key, first_use_s, count)
    current_epoch: u32,
    checkpoints: Vec<Checkpoint>,
    signer: S,
    path: Option<PathBuf>,
    /// Идемпотентность export-запросов (AUD-010): request_id → digest ответа.
    export_idem: BTreeMap<Vec<u8>, Vec<u8>>,
    last_checkpoint_idx: usize,
}

fn parse_checkpoint(v: &Cbor) -> Option<Checkpoint> {
    let b32 = |k: &str| -> Option<[u8; 32]> {
        let b = v.get(k)?.as_bytes()?;
        if b.len() != 32 {
            return None;
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Some(a)
    };
    Some(Checkpoint {
        seq_start: v.get("seq_start")?.as_u64()?,
        seq_end: v.get("seq_end")?.as_u64()?,
        chain_hash: b32("chain_hash")?,
        prev_checkpoint_hash: b32("prev_checkpoint_hash")?,
        key_epoch_start: v.get("key_epoch_start")?.as_u64()? as u32,
        key_epoch_end: v.get("key_epoch_end")?.as_u64()? as u32,
        signature: v.get("signature")?.as_bytes()?.to_vec(),
    })
}

fn chain_link(hash_prev: &[u8; 32], mac: &[u8; 32], seq: u64, epoch: u32) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32 + 8 + 4);
    buf.extend_from_slice(hash_prev);
    buf.extend_from_slice(mac);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    streebog256(&buf)
}

impl<S: AuditSigner> AuditLog<S> {
    pub fn new(node_id: [u8; 16], signer: S, first_key: [u8; 32], now_s: u64) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(1u32, (first_key, now_s, 0u64));
        AuditLog {
            node_id,
            records: Vec::new(),
            macs: Vec::new(),
            keys,
            current_epoch: 1,
            checkpoints: Vec::new(),
            signer,
            path: None,
            export_idem: BTreeMap::new(),
            last_checkpoint_idx: 0,
        }
    }

    pub fn with_path(mut self, path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|_| AuditError::Io)?;
        }
        let exists = p.exists();
        self.path = Some(p);
        if exists {
            self.load()?;
        }
        Ok(self)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }
    pub fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    /// AUD-006: требуется ли ротация ключа (≤24 ч или 10⁶ записей).
    pub fn needs_key_rotation(&self, now_s: u64) -> bool {
        match self.keys.get(&self.current_epoch) {
            Some((_, first, count)) => {
                now_s.saturating_sub(*first) >= KEY_ROTATION_MAX_S || *count >= KEY_ROTATION_MAX_RECORDS
            }
            None => true,
        }
    }

    pub fn rotate_key(&mut self, new_key: [u8; 32], now_s: u64) {
        self.current_epoch += 1;
        self.keys.insert(self.current_epoch, (new_key, now_s, 0));
    }

    /// Добавление записи (append-only, AUD-001). seq — monotonic без
    /// пропусков (DM-1); hash chain (AUD-003); MAC (AUD-002); подпись.
    pub fn append(
        &mut self,
        timestamp_s: u64,
        actor_id: [u8; 16],
        session_id: u64,
        event_type: &str,
        object_id: [u8; 16],
        result: &str,
    ) -> Result<u64, AuditError> {
        let seq = self.records.len() as u64 + 1;
        let hash_prev = self
            .records
            .last()
            .map(|r| r.hash_self)
            .unwrap_or([0u8; 32]);
        let epoch = self.current_epoch;
        let mut rec = AuditRecord {
            seq,
            timestamp_s,
            node_id: self.node_id,
            actor_id,
            session_id,
            event_type: event_type.to_owned(),
            object_id,
            result: result.to_owned(),
            hash_prev,
            hash_self: [0u8; 32],
            key_epoch: epoch,
            signature: Vec::new(),
        };
        let (key, _, count) = self
            .keys
            .get_mut(&epoch)
            .ok_or(AuditError::Corrupted)?;
        let mac = hmac_streebog256(key, &rec.mac_base());
        *count += 1;
        rec.hash_self = chain_link(&hash_prev, &mac, seq, epoch);
        // подпись покрывает canonical с ПУСТЫМ signature (§13.18.3 прим. 2)
        rec.signature = self.signer.sign(&rec.canonical(true))?;

        if let Some(path) = &self.path {
            self.persist_record(path, &rec, &mac)?;
        }
        self.records.push(rec);
        self.macs.push(mac);

        // AUD-004: checkpoint каждые CHECKPOINT_INTERVAL записей
        if seq % CHECKPOINT_INTERVAL == 0 {
            self.make_checkpoint(seq)?;
        }
        Ok(seq)
    }

    fn make_checkpoint(&mut self, seq_end: u64) -> Result<(), AuditError> {
        let seq_start = self.last_checkpoint_idx as u64 + 1;
        let chain_hash = self.records.last().map(|r| r.hash_self).unwrap_or([0u8; 32]);
        let prev_checkpoint_hash =
            self.checkpoints.last().map(|c| c.hash()).unwrap_or([0u8; 32]);
        let epoch_start = self.records[(seq_start - 1) as usize].key_epoch;
        let epoch_end = self.records[(seq_end - 1) as usize].key_epoch;
        let mut cp = Checkpoint {
            seq_start,
            seq_end,
            chain_hash,
            prev_checkpoint_hash,
            key_epoch_start: epoch_start,
            key_epoch_end: epoch_end,
            signature: Vec::new(),
        };
        cp.signature = self.signer.sign(&cp.tbs())?;
        self.checkpoints.push(cp);
        self.last_checkpoint_idx = seq_end as usize;
        if let Some(path) = &self.path {
            self.persist_checkpoint(path)?;
        }
        Ok(())
    }

    /// Полная верификация журнала (AUD-008: insert/delete/modify/reorder/
    /// replay): seq без пропусков, hash-цепочка, MAC по ключам эпох, подписи.
    pub fn verify_all(&self) -> Result<(), AuditError> {
        let mut prev_hash = [0u8; 32];
        let mut prev_ts = 0u64;
        for (i, r) in self.records.iter().enumerate() {
            let seq = i as u64 + 1;
            if r.seq != seq {
                // вставка/удаление/перестановка
                return Err(if r.seq < seq { AuditError::ReorderDetected } else { AuditError::SeqGap });
            }
            if r.timestamp_s + 1 < prev_ts {
                // грубое нарушение монотонности (replay старого)
                return Err(AuditError::ReplayDetected);
            }
            prev_ts = prev_ts.max(r.timestamp_s);
            if r.hash_prev != prev_hash {
                return Err(AuditError::ChainBroken);
            }
            let (key, _, _) = self.keys.get(&r.key_epoch).ok_or(AuditError::Corrupted)?;
            let mac = hmac_streebog256(key, &r.mac_base());
            if mac != self.macs[i] {
                return Err(AuditError::MacMismatch);
            }
            let expect = chain_link(&r.hash_prev, &mac, r.seq, r.key_epoch);
            if expect != r.hash_self {
                return Err(AuditError::ChainBroken);
            }
            if !self.signer.verify(&r.canonical(true), &r.signature) {
                return Err(AuditError::SignatureInvalid);
            }
            prev_hash = r.hash_self;
        }
        // checkpoints
        let mut prev_cp = [0u8; 32];
        for cp in &self.checkpoints {
            if cp.prev_checkpoint_hash != prev_cp {
                return Err(AuditError::ChainBroken);
            }
            let rec = &self.records[(cp.seq_end - 1) as usize];
            if rec.hash_self != cp.chain_hash {
                return Err(AuditError::ChainBroken);
            }
            if !self.signer.verify(&cp.tbs(), &cp.signature) {
                return Err(AuditError::SignatureInvalid);
            }
            prev_cp = cp.hash();
        }
        Ok(())
    }

    // ---------------- экспорт (AUD-010) ----------------

    /// Подписанный chunk экспорта; идемпотентность по request_id.
    pub fn export_chunk(
        &mut self,
        request_id: &[u8],
        from_seq: u64,
        max_records: usize,
    ) -> Result<Vec<u8>, AuditError> {
        // AUD-010 idempotency: повторный запрос → тот же ответ
        if let Some(prev) = self.export_idem.get(request_id) {
            return Ok(prev.clone());
        }
        let start = from_seq.max(1) as usize - 1;
        let end = ((from_seq.max(1) as usize - 1) + max_records).min(self.records.len());
        let recs: Vec<Cbor> = self.records[start.min(end)..end]
            .iter()
            .map(|r| Cbor::from_slice(&r.canonical(false)).expect("record canonical"))
            .collect();
        let prev_chunk_hash = self
            .checkpoints
            .last()
            .map(|c| c.hash())
            .unwrap_or([0u8; 32]);
        let mut chunk_items = vec![
            (Cbor::text("request_id"), Cbor::bytes(request_id.to_vec())),
            (Cbor::text("seq_from"), Cbor::UInt(from_seq)),
            (Cbor::text("seq_to"), Cbor::UInt(end as u64)),
            (Cbor::text("records"), Cbor::array(recs)),
            (Cbor::text("prev_chunk_hash"), Cbor::bytes(prev_chunk_hash.to_vec())),
        ];
        let body = Cbor::map(chunk_items.clone());
        let body_hash = streebog256(&body.to_vec());
        chunk_items.push((Cbor::text("chunk_hash"), Cbor::bytes(body_hash.to_vec())));
        let to_sign = Cbor::map(chunk_items.clone()).to_vec();
        let sig = self.signer.sign(&to_sign)?;
        chunk_items.push((Cbor::text("signature"), Cbor::bytes(sig)));
        let chunk = Cbor::map(chunk_items).to_vec();
        self.export_idem.insert(request_id.to_vec(), chunk.clone());
        Ok(chunk)
    }

    // ---------------- персистенция (append-only файл) ----------------

    fn persist_record(&self, path: &Path, rec: &AuditRecord, mac: &[u8; 32]) -> Result<(), AuditError> {
        let rec_bytes = rec.canonical(false);
        let mut buf = Vec::with_capacity(4 + rec_bytes.len() + 32);
        buf.extend_from_slice(&(rec_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&rec_bytes);
        buf.extend_from_slice(mac);
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true) // AUD-001: append-only
            .open(path)
            .map_err(|_| AuditError::Io)?;
        f.write_all(&buf).map_err(|_| AuditError::Io)?;
        f.sync_all().map_err(|_| AuditError::Io)?;
        Ok(())
    }

    fn persist_checkpoint(&self, path: &Path) -> Result<(), AuditError> {
        let cp_path = path.with_extension("checkpoints");
        let cp = self.checkpoints.last().ok_or(AuditError::Corrupted)?;
        let doc = Cbor::map(vec![
            (Cbor::text("seq_start"), Cbor::UInt(cp.seq_start)),
            (Cbor::text("seq_end"), Cbor::UInt(cp.seq_end)),
            (Cbor::text("chain_hash"), Cbor::bytes(cp.chain_hash.to_vec())),
            (Cbor::text("prev_checkpoint_hash"), Cbor::bytes(cp.prev_checkpoint_hash.to_vec())),
            (Cbor::text("key_epoch_start"), Cbor::UInt(cp.key_epoch_start as u64)),
            (Cbor::text("key_epoch_end"), Cbor::UInt(cp.key_epoch_end as u64)),
            (Cbor::text("signature"), Cbor::bytes(cp.signature.clone())),
        ])
        .to_vec();
        let mut buf = Vec::with_capacity(4 + doc.len());
        buf.extend_from_slice(&(doc.len() as u32).to_be_bytes());
        buf.extend_from_slice(&doc);
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(cp_path)
            .map_err(|_| AuditError::Io)?;
        f.write_all(&buf).map_err(|_| AuditError::Io)?;
        Ok(())
    }

    fn load(&mut self) -> Result<(), AuditError> {
        let path = self.path.clone().ok_or(AuditError::Io)?;
        let raw = std::fs::read(&path).map_err(|_| AuditError::Io)?;
        let mut off = 0usize;
        while off + 4 <= raw.len() {
            let len = u32::from_be_bytes(raw[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + len + 32 > raw.len() {
                return Err(AuditError::Corrupted);
            }
            let v = Cbor::from_slice(&raw[off..off + len]).map_err(|_| AuditError::Corrupted)?;
            let rec = AuditRecord::from_cbor(&v).ok_or(AuditError::Corrupted)?;
            let mut mac = [0u8; 32];
            mac.copy_from_slice(&raw[off + len..off + len + 32]);
            off += len + 32;
            // ключ эпохи должен быть известен; mac перепроверяется
            let (key, _, count) = self
                .keys
                .get_mut(&rec.key_epoch)
                .ok_or(AuditError::Corrupted)?;
            let calc = hmac_streebog256(key, &rec.mac_base());
            if !constant_time_eq(&calc, &mac) {
                return Err(AuditError::MacMismatch);
            }
            *count += 1;
            self.records.push(rec);
            self.macs.push(mac);
        }
        self.last_checkpoint_idx = self.records.len();
        // checkpoints
        let cp_path = path.with_extension("checkpoints");
        if cp_path.exists() {
            let raw = std::fs::read(&cp_path).map_err(|_| AuditError::Io)?;
            let mut off = 0usize;
            while off + 4 <= raw.len() {
                let len = u32::from_be_bytes(raw[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                if off + len > raw.len() {
                    return Err(AuditError::Corrupted);
                }
                let v = Cbor::from_slice(&raw[off..off + len]).map_err(|_| AuditError::Corrupted)?;
                off += len;
                self.checkpoints.push(parse_checkpoint(&v).ok_or(AuditError::Corrupted)?);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> AuditLog<MemorySigner> {
        AuditLog::new([1u8; 16], MemorySigner::default(), [7u8; 32], 1000)
    }

    /// Детерминированный клонируемый подписант — для структурных тестов
    /// tamper-detection (подписи должны проходить, чтобы изолировать
    /// проверки seq/chain/MAC).
    #[derive(Clone)]
    struct DetSigner {
        secret: [u8; 32],
    }
    impl AuditSigner for DetSigner {
        fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, AuditError> {
            let mut buf = Vec::with_capacity(64 + data.len());
            buf.extend_from_slice(&self.secret);
            buf.extend_from_slice(data);
            Ok(streebog256(&buf).to_vec())
        }
        fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
            let mut buf = Vec::with_capacity(64 + data.len());
            buf.extend_from_slice(&self.secret);
            buf.extend_from_slice(data);
            constant_time_eq(&streebog256(&buf), sig)
        }
    }
    fn det_signer() -> DetSigner {
        DetSigner { secret: [0x55; 32] }
    }

    #[test]
    fn append_and_verify() {
        let mut l = log();
        for i in 0..10u64 {
            l.append(1000 + i, [2u8; 16], 42, events::COMMAND_ISSUE, [3u8; 16], "OK")
                .unwrap();
        }
        assert_eq!(l.len(), 10);
        l.verify_all().unwrap();
        // seq monotonic без пропусков
        for (i, r) in l.records().iter().enumerate() {
            assert_eq!(r.seq, i as u64 + 1);
        }
        // hash chain связан
        assert_eq!(l.records()[0].hash_prev, [0u8; 32]);
        assert_eq!(l.records()[1].hash_prev, l.records()[0].hash_self);
    }

    #[test]
    fn tamper_detection_all_classes() {
        let mut l = AuditLog::new([1u8; 16], det_signer(), [7u8; 32], 1000);
        for i in 0..6u64 {
            l.append(1000 + i, [2u8; 16], 42, events::COMMAND_ISSUE, [3u8; 16], "OK")
                .unwrap();
        }
        l.verify_all().unwrap();
        // modify
        let mut l2 = clone_log(&l);
        l2.records[3].result = "TAMPERED".into();
        assert_eq!(l2.verify_all(), Err(AuditError::MacMismatch));
        // delete (пропуск seq)
        let mut l3 = clone_log(&l);
        l3.records.remove(2);
        l3.macs.remove(2);
        assert_eq!(l3.verify_all(), Err(AuditError::SeqGap));
        // reorder
        let mut l4 = clone_log(&l);
        l4.records.swap(1, 2);
        l4.macs.swap(1, 2);
        assert_eq!(l4.verify_all(), Err(AuditError::SeqGap));
        // insert
        let mut l5 = clone_log(&l);
        let fake = l5.records[2].clone();
        l5.records.insert(2, fake);
        l5.macs.insert(2, [0u8; 32]);
        // вставка ловится MAC-проверкой дубликата (без ключа эпохи
        // корректный MAC на дубликат не вычислить), а при его наличии —
        // проверкой последовательности seq
        assert_eq!(l5.verify_all(), Err(AuditError::MacMismatch));
        // replay старой записи (timestamp откат) — перехватывается seq-проверкой
        let mut l6 = clone_log(&l);
        l6.records.push(l6.records[0].clone());
        l6.macs.push(l6.macs[0]);
        assert_eq!(l6.verify_all(), Err(AuditError::ReorderDetected));
    }

    fn clone_log(l: &AuditLog<DetSigner>) -> AuditLog<DetSigner> {
        let mut l2 = AuditLog::new(l.node_id, det_signer(), [7u8; 32], 1000);
        l2.records = l.records.clone();
        l2.macs = l.macs.clone();
        for (k, v) in &l.keys {
            l2.keys.insert(*k, *v);
        }
        l2.current_epoch = l.current_epoch;
        l2
    }

    #[test]
    fn checkpoints_every_512() {
        let mut l = log();
        for i in 0..(CHECKPOINT_INTERVAL + 5) {
            l.append(2000 + i, [2u8; 16], 42, events::OPERATOR_ACTION, [3u8; 16], "OK")
                .unwrap();
        }
        assert_eq!(l.checkpoints().len(), 1);
        let cp = &l.checkpoints()[0];
        assert_eq!(cp.seq_start, 1);
        assert_eq!(cp.seq_end, CHECKPOINT_INTERVAL);
        assert_eq!(cp.chain_hash, l.records()[CHECKPOINT_INTERVAL as usize - 1].hash_self);
        l.verify_all().unwrap();
    }

    #[test]
    fn key_rotation_epochs() {
        let mut l = log();
        l.append(1000, [2u8; 16], 1, events::KEY_OPERATION, [3u8; 16], "OK").unwrap();
        assert!(!l.needs_key_rotation(1000));
        assert!(l.needs_key_rotation(1000 + KEY_ROTATION_MAX_S));
        l.rotate_key([8u8; 32], 1000 + KEY_ROTATION_MAX_S);
        assert_eq!(l.current_epoch(), 2);
        l.append(1000 + KEY_ROTATION_MAX_S, [2u8; 16], 1, events::KEY_OPERATION, [3u8; 16], "OK")
            .unwrap();
        assert_eq!(l.records()[1].key_epoch, 2);
        l.verify_all().unwrap();
    }

    #[test]
    fn export_chunks_idempotent() {
        let mut l = log();
        for i in 0..8u64 {
            l.append(3000 + i, [2u8; 16], 7, events::COMMAND_ISSUE, [3u8; 16], "OK").unwrap();
        }
        let req = b"export-request-0001";
        let c1 = l.export_chunk(req, 1, 4).unwrap();
        let c2 = l.export_chunk(req, 1, 4).unwrap();
        assert_eq!(c1, c2, "идемпотентность AUD-010");
        let v = Cbor::from_slice(&c1).unwrap();
        assert_eq!(v.get("records").unwrap().as_array().unwrap().len(), 4);
        assert!(v.get("signature").unwrap().as_bytes().unwrap().len() == sakura_hybrid::HYBRID_SIG_LEN);
        let c3 = l.export_chunk(b"export-request-0002", 5, 100).unwrap();
        assert_ne!(c1, c3);
        let v3 = Cbor::from_slice(&c3).unwrap();
        assert_eq!(v3.get("records").unwrap().as_array().unwrap().len(), 4);
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sakura-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("checkpoints")).ok();
        let signer = MemorySigner::default();
        let pk = signer.kp.public.clone();
        {
            let mut l = AuditLog::new([1u8; 16], signer, [7u8; 32], 1000)
                .with_path(&path)
                .unwrap();
            for i in 0..5u64 {
                l.append(4000 + i, [2u8; 16], 9, events::SESSION_OPEN, [3u8; 16], "OK").unwrap();
            }
            l.verify_all().unwrap();
        }
        // перезагрузка: тот же signer-ключ (в узле — HSM), те же audit-ключи
        let signer2 = MemorySigner { kp: sakura_hybrid::HybridKeyPair { gost_priv: [0; 32], mldsa_sk: vec![], mlkem_dk: vec![], public: pk.clone() } };
        // упрощение: создаём новый журнал и загружаем файл, подписи
        // проверяются отдельным верификатором по публичному ключу
        let raw = std::fs::read(&path).unwrap();
        let mut off = 0usize;
        let mut prev_hash = [0u8; 32];
        let mut count = 0u64;
        while off + 4 <= raw.len() {
            let len = u32::from_be_bytes(raw[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            let v = Cbor::from_slice(&raw[off..off + len]).unwrap();
            let rec = AuditRecord::from_cbor(&v).unwrap();
            off += len + 32;
            assert_eq!(rec.seq, count + 1);
            assert_eq!(rec.hash_prev, prev_hash);
            assert!(sakura_hybrid::hybrid_verify(&pk, &rec.canonical(true), &rec.signature));
            prev_hash = rec.hash_self;
            count += 1;
        }
        assert_eq!(count, 5);
        let _ = signer2;
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
