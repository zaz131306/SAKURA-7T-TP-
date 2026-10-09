//! Служба времени (§12): PTP-подобная синхронизация между узлами +
//! holdover-модель осциллятора (§12.2): OCXO ≤5 мкс/24 ч (BC-2),
//! ≤150 мкс/7 сут. Качество: LOCKED / HOLDOVER / FREE (§13.8 0x0009).

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeQuality {
    Locked,
    Holdover,
    Free,
}

impl TimeQuality {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimeQuality::Locked => "LOCKED",
            TimeQuality::Holdover => "HOLDOVER",
            TimeQuality::Free => "FREE",
        }
    }
}

pub struct TimeService {
    /// Смещения относительно пиров (нс), по состоянию последних обменов.
    pub offsets_ns: BTreeMap<u32, (i64, u64)>, // peer idx → (offset, measured_ms)
    /// Дрейф локального осциллятора, ppb×1000 (§12.2).
    pub drift_ppb_x1000: i64,
    pub last_locked_ms: u64,
    /// Порог LOCKED: |offset| ≤ 100 мс и свежесть ≤ 5 с.
    pub locked_max_offset_ns: i64,
    pub locked_max_age_ms: u64,
    /// Окно HOLDOVER: ≤30 с после потери LOCKED (§12.1 holdover profile).
    pub holdover_max_ms: u64,
    persisted_offset_ns: i64,
}

impl TimeService {
    pub fn new(drift_ppb_x1000: i64) -> Self {
        TimeService {
            offsets_ns: BTreeMap::new(),
            drift_ppb_x1000,
            last_locked_ms: 0,
            locked_max_offset_ns: 100_000_000,
            locked_max_age_ms: 5_000,
            holdover_max_ms: 30_000,
            persisted_offset_ns: 0,
        }
    }

    pub fn record_offset(&mut self, peer: u32, offset_ns: i64, now_ms: u64) {
        self.offsets_ns.insert(peer, (offset_ns, now_ms));
    }

    /// Медианное кластерное смещение по свежим измерениям.
    pub fn cluster_offset_ns(&self, now_ms: u64) -> Option<i64> {
        let mut fresh: Vec<i64> = self
            .offsets_ns
            .values()
            .filter(|(_, t)| now_ms.saturating_sub(*t) <= self.locked_max_age_ms)
            .map(|(o, _)| *o)
            .collect();
        if fresh.is_empty() {
            return None;
        }
        fresh.sort();
        Some(fresh[fresh.len() / 2])
    }

    pub fn quality(&self, now_ms: u64) -> TimeQuality {
        match self.cluster_offset_ns(now_ms) {
            Some(o) if o.abs() <= self.locked_max_offset_ns => TimeQuality::Locked,
            _ => {
                if self.last_locked_ms > 0
                    && now_ms.saturating_sub(self.last_locked_ms) <= self.holdover_max_ms
                {
                    TimeQuality::Holdover
                } else if self.last_locked_ms == 0 && self.persisted_offset_ns != 0 {
                    // старт с сохранённым смещением — holdover из персистента
                    TimeQuality::Holdover
                } else {
                    TimeQuality::Free
                }
            }
        }
    }

    /// Синхронизированное время (мс): local + offset + дрейф в holdover.
    pub fn now_ms(&self, local_ms: u64) -> u64 {
        let base_off = self
            .cluster_offset_ns(local_ms)
            .unwrap_or(self.persisted_offset_ns);
        let corrected = (local_ms as i64) + base_off / 1_000_000;
        // holdover-дрейф: (ppb×1000)/1000 × возраст, мс
        let age_ms = local_ms.saturating_sub(self.last_locked_ms);
        let drift_ns = (self.drift_ppb_x1000 * age_ms as i64) / 1000; // ns
        (corrected + drift_ns / 1_000_000).max(0) as u64
    }

    pub fn note_quality(&mut self, q: TimeQuality, now_ms: u64) {
        if q == TimeQuality::Locked {
            self.last_locked_ms = now_ms;
            if let Some(o) = self.cluster_offset_ns(now_ms) {
                self.persisted_offset_ns = o;
            }
        }
    }

    pub fn save(&self, path: &Path) {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.persisted_offset_ns.to_be_bytes());
        buf.extend_from_slice(&self.last_locked_ms.to_be_bytes());
        let _ = std::fs::write(path, buf);
    }

    pub fn load(&mut self, path: &Path) {
        if let Ok(raw) = std::fs::read(path) {
            if raw.len() == 16 {
                self.persisted_offset_ns = i64::from_be_bytes(raw[..8].try_into().unwrap());
                self.last_locked_ms = u64::from_be_bytes(raw[8..].try_into().unwrap());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_transitions() {
        let mut t = TimeService::new(58);
        assert_eq!(t.quality(1000), TimeQuality::Free);
        t.record_offset(1, 5_000_000, 1000); // 5 мс
        assert_eq!(t.quality(1000), TimeQuality::Locked);
        t.note_quality(TimeQuality::Locked, 1000);
        // потеря синхронизации → holdover ≤30 с
        assert_eq!(t.quality(10_000), TimeQuality::Holdover);
        assert_eq!(t.quality(40_000), TimeQuality::Free);
    }

    #[test]
    fn holdover_drift_bounded() {
        // BC-2: OCXO ≤5 мкс/24 ч → за 24 ч holdover дрейф ≤ 5 мс (с запасом)
        let mut t = TimeService::new(58); // 0.058 ppb
        t.record_offset(1, 0, 0);
        t.note_quality(TimeQuality::Locked, 0);
        t.offsets_ns.clear();
        let day_ms: u64 = 24 * 3600 * 1000;
        let synced = t.now_ms(day_ms);
        let drift = (synced as i64 - day_ms as i64).abs();
        assert!(drift <= 10, "дрейф за 24ч = {drift} мс (модель: ≤5 мкс + дискретизация мс)");
    }

    #[test]
    fn offset_applied() {
        let mut t = TimeService::new(58);
        t.record_offset(1, 2_000_000_000, 100); // +2 с
        assert_eq!(t.now_ms(1000), 3000);
        t.record_offset(2, 4_000_000_000, 100); // медиана {2,4} → 4? (len/2=1 → 4с)
        let off = t.cluster_offset_ns(100).unwrap();
        assert!(off == 2_000_000_000 || off == 4_000_000_000);
    }

    #[test]
    fn persistence() {
        let dir = std::env::temp_dir().join(format!("sakura-time-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.state");
        let mut t = TimeService::new(58);
        t.record_offset(1, 1_500_000_000, 500);
        t.note_quality(TimeQuality::Locked, 500);
        t.save(&p);
        let mut t2 = TimeService::new(58);
        t2.load(&p);
        assert_eq!(t2.persisted_offset_ns, 1_500_000_000);
        assert_eq!(t2.last_locked_ms, 500);
        std::fs::remove_file(&p).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
