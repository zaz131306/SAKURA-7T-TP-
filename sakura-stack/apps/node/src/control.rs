//! Control-плоскость: идемпотентность (IDEMP-001, BC-27), защита от replay
//! (REPLAY-001), хранение результатов команд.
//!
//! ```text
//! IDEMP-001: idempotency key привязан к actor, session, command type,
//! payload hash и time window; повторный запрос возвращает предыдущий
//! результат, не повторяя побочный эффект; store защищён от rollback.
//! ```

use sakura_common::cbor::Cbor;
use sakura_gost::hash::{constant_time_eq, hmac_streebog256, streebog256};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct IdemEntry {
    pub result: String,
    pub audit_ref: [u8; 16],
    pub audit_seq: u64,
    pub ts: u64,
}

pub struct IdemStore {
    /// command_id → результат (после финализации консенсусом).
    by_command: BTreeMap<[u8; 16], IdemEntry>,
    /// idempotency_key (HMAC-связка) → command_id.
    by_key: BTreeMap<Vec<u8>, [u8; 16]>,
    /// Ожидание финализации: command_id → (idem_key).
    pending: BTreeMap<[u8; 16], Vec<u8>>,
    /// Монотонный seq на принципала (REPLAY-001).
    principal_seq: BTreeMap<[u8; 16], u64>,
    /// Одноразовые nonce attestation (§13.19.2).
    used_nonces: BTreeMap<[u8; 32], u64>,
    mac_key: [u8; 32],
    /// Монотонный счётчик снимков (защита store от rollback, IDEMP-001).
    snapshot_counter: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdemError {
    ReplayDetected,
    SeqOutOfWindow,
    NonceReused,
    Rollback,
    Corrupted,
}

/// Окно привязки idempotency key — 1 час (DM-1: session expires ≤1 ч).
const IDEM_WINDOW_S: u64 = 3600;

impl IdemStore {
    pub fn new(mac_key: [u8; 32]) -> Self {
        IdemStore {
            by_command: BTreeMap::new(),
            by_key: BTreeMap::new(),
            pending: BTreeMap::new(),
            principal_seq: BTreeMap::new(),
            used_nonces: BTreeMap::new(),
            mac_key,
            snapshot_counter: 0,
        }
    }

    /// IDEMP-001: ключ = HMAC(actor | session | cmd_type | payload_hash | window).
    pub fn idem_key(actor: &[u8; 16], session: u64, cmd_type: &str, payload: &[u8], now_s: u64) -> Vec<u8> {
        let mut base = Vec::new();
        base.extend_from_slice(actor);
        base.extend_from_slice(&session.to_be_bytes());
        base.extend_from_slice(cmd_type.as_bytes());
        base.extend_from_slice(&streebog256(payload));
        base.extend_from_slice(&(now_s / IDEM_WINDOW_S).to_be_bytes());
        hmac_streebog256(&base, b"SAKURA-IDEM-KEY-V1").to_vec()
    }

    /// Проверка seq принципала (REPLAY-001: monotonic seq).
    pub fn check_principal_seq(&mut self, principal: &[u8; 16], seq: u64) -> Result<(), IdemError> {
        let last = self.principal_seq.get(principal).copied().unwrap_or(0);
        if seq <= last {
            if seq == last {
                return Err(IdemError::ReplayDetected);
            }
            return Err(IdemError::SeqOutOfWindow);
        }
        self.principal_seq.insert(*principal, seq);
        Ok(())
    }

    /// Одноразовый nonce (§13.19.2: nonce одноразовый).
    pub fn consume_nonce(&mut self, nonce: &[u8], now_s: u64) -> Result<(), IdemError> {
        if nonce.len() < 16 {
            return Err(IdemError::Corrupted);
        }
        let mut n = [0u8; 32];
        n[..nonce.len().min(32)].copy_from_slice(&nonce[..nonce.len().min(32)]);
        // очистка старых nonce (окно 1 ч)
        self.used_nonces.retain(|_, t| now_s.saturating_sub(*t) < IDEM_WINDOW_S);
        if self.used_nonces.insert(n, now_s).is_some() {
            return Err(IdemError::NonceReused);
        }
        Ok(())
    }

    /// Уже обработанная команда? → сохранить/вернуть прежний результат.
    pub fn known_command(&self, command_id: &[u8; 16]) -> Option<&IdemEntry> {
        self.by_command.get(command_id)
    }

    pub fn known_key(&self, key: &[u8]) -> Option<&[u8; 16]> {
        self.by_key.get(key)
    }

    pub fn mark_pending(&mut self, command_id: [u8; 16], idem_key: Vec<u8>) {
        self.pending.insert(command_id, idem_key);
    }

    pub fn resolve(&mut self, command_id: &[u8; 16], entry: IdemEntry) {
        if let Some(key) = self.pending.remove(command_id) {
            self.by_key.insert(key, *command_id);
        }
        self.by_command.insert(*command_id, entry);
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    // ---- персистенция с защитой от rollback ----

    pub fn save(&mut self, path: &Path) -> Result<(), IdemError> {
        self.snapshot_counter += 1;
        let cmds: Vec<Cbor> = self
            .by_command
            .iter()
            .map(|(id, e)| {
                Cbor::map(vec![
                    (Cbor::text("id"), Cbor::bytes(id.to_vec())),
                    (Cbor::text("result"), Cbor::text(e.result.clone())),
                    (Cbor::text("audit_ref"), Cbor::bytes(e.audit_ref.to_vec())),
                    (Cbor::text("audit_seq"), Cbor::UInt(e.audit_seq)),
                    (Cbor::text("ts"), Cbor::UInt(e.ts)),
                ])
            })
            .collect();
        let keys: Vec<Cbor> = self
            .by_key
            .iter()
            .map(|(k, id)| {
                Cbor::map(vec![
                    (Cbor::text("k"), Cbor::bytes(k.clone())),
                    (Cbor::text("id"), Cbor::bytes(id.to_vec())),
                ])
            })
            .collect();
        let seqs: Vec<Cbor> = self
            .principal_seq
            .iter()
            .map(|(p, s)| {
                Cbor::map(vec![
                    (Cbor::text("p"), Cbor::bytes(p.to_vec())),
                    (Cbor::text("s"), Cbor::UInt(*s)),
                ])
            })
            .collect();
        let doc = Cbor::map(vec![
            (Cbor::text("snapshot_counter"), Cbor::UInt(self.snapshot_counter)),
            (Cbor::text("commands"), Cbor::array(cmds)),
            (Cbor::text("keys"), Cbor::array(keys)),
            (Cbor::text("principal_seq"), Cbor::array(seqs)),
        ])
        .to_vec();
        let mac = hmac_streebog256(&self.mac_key, &[b"SAKURA-IDEM-V1".as_slice(), &doc].concat());
        let mut out = Vec::with_capacity(doc.len() + 32);
        out.extend_from_slice(&doc);
        out.extend_from_slice(&mac);
        std::fs::write(path, &out).map_err(|_| IdemError::Corrupted)
    }

    pub fn load(&mut self, path: &Path) -> Result<(), IdemError> {
        if !path.exists() {
            return Ok(());
        }
        let raw = std::fs::read(path).map_err(|_| IdemError::Corrupted)?;
        if raw.len() < 42 {
            return Err(IdemError::Corrupted);
        }
        let (doc, mac) = raw.split_at(raw.len() - 32);
        let calc = hmac_streebog256(&self.mac_key, &[b"SAKURA-IDEM-V1".as_slice(), doc].concat());
        if !constant_time_eq(&calc, mac) {
            return Err(IdemError::Corrupted);
        }
        let v = Cbor::from_slice(doc).map_err(|_| IdemError::Corrupted)?;
        let counter = v.get("snapshot_counter").and_then(|x| x.as_u64()).unwrap_or(0);
        // защита от rollback снапшота (IDEMP-001)
        if counter < self.snapshot_counter {
            return Err(IdemError::Rollback);
        }
        self.snapshot_counter = counter;
        let b16 = |b: &[u8]| -> Option<[u8; 16]> {
            if b.len() != 16 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(a)
        };
        if let Some(arr) = v.get("commands").and_then(|x| x.as_array()) {
            for c in arr {
                let id = b16(c.get("id").and_then(|x| x.as_bytes()).unwrap_or(&[])).ok_or(IdemError::Corrupted)?;
                let mut ref16 = [0u8; 16];
                if let Some(r) = c.get("audit_ref").and_then(|x| x.as_bytes()) {
                    if r.len() == 16 {
                        ref16.copy_from_slice(r);
                    }
                }
                self.by_command.insert(
                    id,
                    IdemEntry {
                        result: c.get("result").and_then(|x| x.as_text()).unwrap_or("OK").to_owned(),
                        audit_ref: ref16,
                        audit_seq: c.get("audit_seq").and_then(|x| x.as_u64()).unwrap_or(0),
                        ts: c.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
                    },
                );
            }
        }
        if let Some(arr) = v.get("keys").and_then(|x| x.as_array()) {
            for c in arr {
                let k = c.get("k").and_then(|x| x.as_bytes()).ok_or(IdemError::Corrupted)?.to_vec();
                let id = b16(c.get("id").and_then(|x| x.as_bytes()).unwrap_or(&[])).ok_or(IdemError::Corrupted)?;
                self.by_key.insert(k, id);
            }
        }
        if let Some(arr) = v.get("principal_seq").and_then(|x| x.as_array()) {
            for c in arr {
                let p = b16(c.get("p").and_then(|x| x.as_bytes()).unwrap_or(&[])).ok_or(IdemError::Corrupted)?;
                self.principal_seq.insert(p, c.get("s").and_then(|x| x.as_u64()).unwrap_or(0));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idem_key_binding() {
        let k1 = IdemStore::idem_key(&[1u8; 16], 5, "KV_PUT", b"v", 1000);
        let k2 = IdemStore::idem_key(&[1u8; 16], 5, "KV_PUT", b"v", 1000);
        assert_eq!(k1, k2);
        // другой actor / session / type / payload / window → другой ключ
        assert_ne!(k1, IdemStore::idem_key(&[2u8; 16], 5, "KV_PUT", b"v", 1000));
        assert_ne!(k1, IdemStore::idem_key(&[1u8; 16], 6, "KV_PUT", b"v", 1000));
        assert_ne!(k1, IdemStore::idem_key(&[1u8; 16], 5, "KV_DEL", b"v", 1000));
        assert_ne!(k1, IdemStore::idem_key(&[1u8; 16], 5, "KV_PUT", b"w", 1000));
        assert_ne!(k1, IdemStore::idem_key(&[1u8; 16], 5, "KV_PUT", b"v", 1000 + IDEM_WINDOW_S));
    }

    #[test]
    fn principal_seq_replay() {
        let mut s = IdemStore::new([3u8; 32]);
        let p = [7u8; 16];
        assert_eq!(s.check_principal_seq(&p, 1), Ok(()));
        assert_eq!(s.check_principal_seq(&p, 2), Ok(()));
        assert_eq!(s.check_principal_seq(&p, 2), Err(IdemError::ReplayDetected));
        assert_eq!(s.check_principal_seq(&p, 1), Err(IdemError::SeqOutOfWindow));
        assert_eq!(s.check_principal_seq(&p, 3), Ok(()));
    }

    #[test]
    fn nonce_one_time() {
        let mut s = IdemStore::new([3u8; 32]);
        let n = [0xAB; 32];
        assert_eq!(s.consume_nonce(&n, 100), Ok(()));
        assert_eq!(s.consume_nonce(&n, 101), Err(IdemError::NonceReused));
        assert!(matches!(s.consume_nonce(&[1u8; 8], 100), Err(IdemError::Corrupted)));
    }

    #[test]
    fn command_result_reuse() {
        let mut s = IdemStore::new([3u8; 32]);
        let id = [1u8; 16];
        let key = IdemStore::idem_key(&[2u8; 16], 1, "KV_PUT", b"x", 100);
        s.mark_pending(id, key.clone());
        assert_eq!(s.pending_count(), 1);
        assert!(s.known_command(&id).is_none());
        s.resolve(&id, IdemEntry { result: "OK".into(), audit_ref: [4u8; 16], audit_seq: 9, ts: 100 });
        assert_eq!(s.pending_count(), 0);
        let e = s.known_command(&id).unwrap();
        assert_eq!(e.result, "OK");
        assert_eq!(e.audit_seq, 9);
        assert_eq!(s.known_key(&key), Some(&id));
    }

    #[test]
    fn persistence_and_rollback_guard() {
        let dir = std::env::temp_dir().join(format!("sakura-idem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("idem.bin");
        let mut s = IdemStore::new([5u8; 32]);
        let id = [1u8; 16];
        s.mark_pending(id, vec![9u8; 32]);
        s.resolve(&id, IdemEntry { result: "OK".into(), audit_ref: [4u8; 16], audit_seq: 2, ts: 50 });
        s.check_principal_seq(&[6u8; 16], 10).unwrap();
        s.save(&path).unwrap();

        let mut s2 = IdemStore::new([5u8; 32]);
        s2.load(&path).unwrap();
        assert_eq!(s2.known_command(&id).unwrap().audit_seq, 2);
        assert_eq!(s2.check_principal_seq(&[6u8; 16], 10), Err(IdemError::ReplayDetected));
        assert_eq!(s2.check_principal_seq(&[6u8; 16], 11), Ok(()));

        // откат снапшота запрещён (IDEMP-001): s2 уже имеет counter=1,
        // повторная загрузка того же файла допустима (counter равен),
        // а вот загрузка МЛАДШЕГО counter — Rollback
        s2.snapshot_counter = 5;
        assert_eq!(s2.load(&path), Err(IdemError::Rollback));
        // тамперинг файла
        let mut raw = std::fs::read(&path).unwrap();
        raw[5] ^= 1;
        std::fs::write(&path, &raw).unwrap();
        let mut s3 = IdemStore::new([5u8; 32]);
        assert_eq!(s3.load(&path), Err(IdemError::Corrupted));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
