//! Rollback-счётчики (BC-24 / UPDATE-ROLLBACK-001, §22.15, §22.9):
//!
//! ```text
//! MUST: active rollback counter не увеличивается до успешного boot и
//!       self-test нового образа.
//! MUST: pending rollback counter хранится отдельно от active.
//! MUST: при неудачном boot активный rollback counter остаётся прежним.
//! MUST: повторные неудачи приводят к recovery/lockdown по политике.
//! MUST: recovery mode не обходит signature, rollback policy и pending
//!       metadata validation.
//! ```
//!
//! Носитель: эмуляция FRAM/MRAM с MAC (§22.9: критические состояния в
//! FRAM/MRAM с MAC) — файл + HMAC-Стрибог-256 под ключом устройства.

use sakura_common::cbor::Cbor;
use sakura_gost::hash::{constant_time_eq, hmac_streebog256};
use std::path::Path;

/// Счётчики по типам образов (image_type 1..4 → индекс 0..3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeCounters {
    pub active: u32,
    pub pending: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackError {
    /// Попытка уменьшить active-счётчик (rollback) — §13.8 0x000C CRITICAL.
    RollbackDetected,
    NoPending,
    Io,
    MacMismatch,
    Corrupted,
}

#[derive(Clone, Debug)]
pub struct RollbackStore {
    counters: [TypeCounters; 4],
    /// BOOT_FAIL_COUNT (§13.16.1: ≥3 → RECOVERY_MODE).
    pub boot_fail_count: u32,
    mac_key: [u8; 32],
}

const MAC_LABEL: &[u8] = b"SAKURA-ROLLBACK-V1";

impl RollbackStore {
    pub fn new(mac_key: [u8; 32]) -> Self {
        RollbackStore {
            counters: [TypeCounters { active: 0, pending: None }; 4],
            boot_fail_count: 0,
            mac_key,
        }
    }

    fn idx(image_type: u8) -> Result<usize, RollbackError> {
        if !(1..=4).contains(&image_type) {
            return Err(RollbackError::Corrupted);
        }
        Ok(image_type as usize - 1)
    }

    pub fn active(&self, image_type: u8) -> u32 {
        self.counters[Self::idx(image_type).unwrap_or(0)].active
    }

    pub fn pending(&self, image_type: u8) -> Option<u32> {
        self.counters[Self::idx(image_type).unwrap_or(0)].pending
    }

    /// min_versions для DeviceState (активные счётчики).
    pub fn min_versions(&self) -> [u32; 4] {
        [
            self.counters[0].active,
            self.counters[1].active,
            self.counters[2].active,
            self.counters[3].active,
        ]
    }

    /// SET_PENDING_METADATA (§13.16.2 Update FSM): pending хранится ОТДЕЛЬНО.
    pub fn set_pending(&mut self, image_type: u8, value: u32) -> Result<(), RollbackError> {
        let i = Self::idx(image_type)?;
        self.counters[i].pending = Some(value);
        Ok(())
    }

    /// COMMIT_ROLLBACK_COUNTER — ТОЛЬКО после successful boot + self-test
    /// (BC-24). pending < active → RollbackDetected (атака отката).
    pub fn commit_pending(&mut self, image_type: u8) -> Result<u32, RollbackError> {
        let i = Self::idx(image_type)?;
        let pending = self.counters[i].pending.ok_or(RollbackError::NoPending)?;
        if pending < self.counters[i].active {
            // rollback-атака: active НЕ уменьшается, событие CRITICAL
            self.counters[i].pending = None;
            return Err(RollbackError::RollbackDetected);
        }
        self.counters[i].active = pending;
        self.counters[i].pending = None;
        Ok(pending)
    }

    /// Неудачный boot: pending отбрасывается, active НЕ изменяется (BC-24).
    pub fn discard_pending(&mut self, image_type: u8) -> Result<(), RollbackError> {
        let i = Self::idx(image_type)?;
        self.counters[i].pending = None;
        Ok(())
    }

    pub fn note_boot_failure(&mut self) {
        self.boot_fail_count = self.boot_fail_count.saturating_add(1);
    }

    pub fn note_boot_success(&mut self) {
        self.boot_fail_count = 0;
    }

    // ---- персистенция (FRAM-эмуляция с MAC) ----

    fn doc(&self) -> Vec<u8> {
        let counters: Vec<Cbor> = self
            .counters
            .iter()
            .map(|c| {
                Cbor::map(vec![
                    (Cbor::text("active"), Cbor::UInt(c.active as u64)),
                    (
                        Cbor::text("pending"),
                        c.pending.map(|p| Cbor::UInt(p as u64)).unwrap_or(Cbor::Null),
                    ),
                ])
            })
            .collect();
        Cbor::map(vec![
            (Cbor::text("version"), Cbor::UInt(1)),
            (Cbor::text("boot_fail_count"), Cbor::UInt(self.boot_fail_count as u64)),
            (Cbor::text("counters"), Cbor::array(counters)),
        ])
        .to_vec()
    }

    pub fn save(&self, path: &Path) -> Result<(), RollbackError> {
        let doc = self.doc();
        let mac = hmac_streebog256(&self.mac_key, &[MAC_LABEL, &doc].concat());
        let mut out = Vec::with_capacity(doc.len() + 32);
        out.extend_from_slice(&doc);
        out.extend_from_slice(&mac);
        std::fs::write(path, &out).map_err(|_| RollbackError::Io)
    }

    pub fn load(path: &Path, mac_key: [u8; 32]) -> Result<Self, RollbackError> {
        let raw = std::fs::read(path).map_err(|_| RollbackError::Io)?;
        if raw.len() < 32 + 10 {
            return Err(RollbackError::Corrupted);
        }
        let (doc, mac) = raw.split_at(raw.len() - 32);
        let calc = hmac_streebog256(&mac_key, &[MAC_LABEL, doc].concat());
        if !constant_time_eq(&calc, mac) {
            return Err(RollbackError::MacMismatch);
        }
        let v = Cbor::from_slice(doc).map_err(|_| RollbackError::Corrupted)?;
        let boot_fail_count =
            v.get("boot_fail_count").and_then(|x| x.as_u64()).ok_or(RollbackError::Corrupted)? as u32;
        let arr = v.get("counters").and_then(|x| x.as_array()).ok_or(RollbackError::Corrupted)?;
        if arr.len() != 4 {
            return Err(RollbackError::Corrupted);
        }
        let mut counters = [TypeCounters { active: 0, pending: None }; 4];
        for (i, c) in arr.iter().enumerate() {
            counters[i].active =
                c.get("active").and_then(|x| x.as_u64()).ok_or(RollbackError::Corrupted)? as u32;
            counters[i].pending = match c.get("pending") {
                Some(Cbor::UInt(p)) => Some(*p as u32),
                Some(Cbor::Null) => None,
                _ => return Err(RollbackError::Corrupted),
            };
        }
        Ok(RollbackStore { counters, boot_fail_count, mac_key })
    }

    /// Загрузка с откатом к новому хранилищу при отсутствии файла.
    pub fn load_or_new(path: &Path, mac_key: [u8; 32]) -> Result<Self, RollbackError> {
        if path.exists() {
            Self::load(path, mac_key)
        } else {
            Ok(Self::new(mac_key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KT: [u8; 32] = [9u8; 32];

    #[test]
    fn bc24_commit_semantics() {
        let mut s = RollbackStore::new(KT);
        // pending отдельно от active
        s.set_pending(2, 5).unwrap();
        assert_eq!(s.active(2), 0);
        assert_eq!(s.pending(2), Some(5));
        // неудачный boot: discard — active прежний (BC-24 MUST)
        s.discard_pending(2).unwrap();
        assert_eq!(s.active(2), 0);
        assert_eq!(s.pending(2), None);
        // успешный boot: commit
        s.set_pending(2, 5).unwrap();
        assert_eq!(s.commit_pending(2).unwrap(), 5);
        assert_eq!(s.active(2), 5);
        assert_eq!(s.pending(2), None);
        // rollback-атака: pending < active → RollbackDetected, active цел
        s.set_pending(2, 3).unwrap();
        assert_eq!(s.commit_pending(2), Err(RollbackError::RollbackDetected));
        assert_eq!(s.active(2), 5, "active НЕ уменьшается (BC-24)");
        // commit без pending
        assert_eq!(s.commit_pending(2), Err(RollbackError::NoPending));
        // min_versions
        s.set_pending(1, 7).unwrap();
        s.commit_pending(1).unwrap();
        assert_eq!(s.min_versions(), [7, 5, 0, 0]); // image_type 1→7, type 2→5
    }

    #[test]
    fn boot_fail_counting() {
        let mut s = RollbackStore::new(KT);
        s.note_boot_failure();
        s.note_boot_failure();
        assert_eq!(s.boot_fail_count, 2);
        s.note_boot_success();
        assert_eq!(s.boot_fail_count, 0);
    }

    #[test]
    fn persistence_mac() {
        let dir = std::env::temp_dir().join(format!("sakura-rb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rollback.bin");
        let mut s = RollbackStore::new(KT);
        s.set_pending(2, 4).unwrap();
        s.commit_pending(2).unwrap();
        s.note_boot_failure();
        s.save(&path).unwrap();

        let l = RollbackStore::load(&path, KT).unwrap();
        assert_eq!(l.active(2), 4);
        assert_eq!(l.boot_fail_count, 1);
        // чужой MAC-ключ → MacMismatch
        assert!(matches!(RollbackStore::load(&path, [1u8; 32]), Err(RollbackError::MacMismatch)));
        // тамперинг файла → MacMismatch
        let mut raw = std::fs::read(&path).unwrap();
        raw[10] ^= 1;
        std::fs::write(&path, &raw).unwrap();
        assert!(matches!(RollbackStore::load(&path, KT), Err(RollbackError::MacMismatch)));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
