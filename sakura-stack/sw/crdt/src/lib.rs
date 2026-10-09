//! CRDT engine (C-06, BC-34 / CRDT-REG-001, ТП §27.9):
//!
//! ```text
//! MUST: concurrent register updates разрешаются детерминированно во всех
//!       репликах.
//! MUST: nondeterministic discard запрещён.
//! MUST: tie-break основан на canonical fields: timestamp, node_id, value_hash.
//! MUST: результат merge сопровождается audit event без чувствительных данных.
//! ```
//!
//! happens_before — канонический по объединению ключей (C-06).

use sakura_common::cbor::Cbor;
use sakura_gost::hash::streebog256;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorClock(pub BTreeMap<NodeId, u64>);

impl VectorClock {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn increment(&mut self, node: NodeId) {
        *self.0.entry(node).or_insert(0) += 1;
    }

    pub fn merge(&mut self, other: &VectorClock) {
        for (k, v) in &other.0 {
            let entry = self.0.entry(*k).or_insert(0);
            *entry = (*entry).max(*v);
        }
    }

    /// Канонический happens-before по объединению ключей (C-06):
    /// self < other ⇔ ∀k: self[k] ≤ other[k] и ∃k: self[k] < other[k].
    /// Отсутствующий ключ = 0.
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        let mut all_keys = BTreeMap::new();
        for (k, v) in &self.0 {
            all_keys.insert(*k, *v);
        }
        for k in other.0.keys() {
            all_keys.entry(*k).or_insert(0);
        }
        let mut strictly_less = false;
        for k in all_keys.keys() {
            let a = self.0.get(k).copied().unwrap_or(0);
            let b = other.0.get(k).copied().unwrap_or(0);
            if a > b {
                return false;
            }
            if a < b {
                strictly_less = true;
            }
        }
        strictly_less
    }

    pub fn is_concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self) && self != other
    }

    pub fn to_cbor(&self) -> Cbor {
        Cbor::map(self.0.iter().map(|(k, v)| (Cbor::UInt(k.0), Cbor::UInt(*v))).collect::<Vec<_>>())
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let mut m = BTreeMap::new();
        if let Cbor::Map(items) = v {
            for (k, val) in items {
                m.insert(NodeId(k.as_u64()?), val.as_u64()?);
            }
        } else {
            return None;
        }
        Some(VectorClock(m))
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LwwMetadata {
    pub timestamp: u64,
    pub node_id: NodeId,
    pub value_hash: [u8; 32],
}

impl LwwMetadata {
    pub fn new(timestamp: u64, node_id: NodeId, value: &[u8]) -> Self {
        LwwMetadata { timestamp, node_id, value_hash: streebog256(value) }
    }

    pub fn to_cbor(&self) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("timestamp"), Cbor::UInt(self.timestamp)),
            (Cbor::text("node_id"), Cbor::UInt(self.node_id.0)),
            (Cbor::text("value_hash"), Cbor::bytes(self.value_hash.to_vec())),
        ])
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let b = v.get("value_hash")?.as_bytes()?;
        if b.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(b);
        Some(LwwMetadata {
            timestamp: v.get("timestamp")?.as_u64()?,
            node_id: NodeId(v.get("node_id")?.as_u64()?),
            value_hash: h,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CrdtValue {
    Counter(BTreeMap<NodeId, u64>),
    Register {
        value: Vec<u8>,
        clock: VectorClock,
        lww: LwwMetadata,
    },
}

#[derive(Clone, Debug)]
pub enum CrdtOp {
    Increment { node: NodeId, delta: u64 },
    Set { value: Vec<u8>, clock: VectorClock, lww: LwwMetadata },
}

impl CrdtOp {
    /// Каноническая CBOR-сериализация операции (транспорт NPP/consensus).
    pub fn to_cbor(&self, kind: u8) -> Cbor {
        let mut items = vec![(Cbor::text("kind"), Cbor::UInt(kind as u64))];
        match self {
            CrdtOp::Increment { node, delta } => {
                items.push((Cbor::text("op"), Cbor::text("inc")));
                items.push((Cbor::text("node"), Cbor::UInt(node.0)));
                items.push((Cbor::text("delta"), Cbor::UInt(*delta)));
            }
            CrdtOp::Set { value, clock, lww } => {
                items.push((Cbor::text("op"), Cbor::text("set")));
                items.push((Cbor::text("value"), Cbor::bytes(value.clone())));
                items.push((Cbor::text("clock"), clock.to_cbor()));
                items.push((Cbor::text("lww"), lww.to_cbor()));
            }
        }
        Cbor::map(items)
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        match v.get("op")?.as_text()? {
            "inc" => Some(CrdtOp::Increment {
                node: NodeId(v.get("node")?.as_u64()?),
                delta: v.get("delta")?.as_u64()?,
            }),
            "set" => Some(CrdtOp::Set {
                value: v.get("value")?.as_bytes()?.to_vec(),
                clock: VectorClock::from_cbor(v.get("clock")?)?,
                lww: LwwMetadata::from_cbor(v.get("lww")?)?,
            }),
            _ => None,
        }
    }
}

/// Аудит-событие merge (CRDT-REG-001: без чувствительных данных —
/// только key, исход и канонические поля tie-break).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeAudit {
    Accepted { key: String, timestamp: u64, node_id: u64 },
    RejectedOlder { key: String },
    ConcurrentTieBreak { key: String, winner_node: u64, winner_ts: u64, by: &'static str },
}

pub struct CrdtEngine {
    state: BTreeMap<String, CrdtValue>,
    audit: Vec<MergeAudit>,
}

impl Default for CrdtEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CrdtEngine {
    pub fn new() -> Self {
        Self { state: BTreeMap::new(), audit: Vec::new() }
    }

    pub fn apply(&mut self, key: &str, op: CrdtOp) {
        match op {
            CrdtOp::Increment { node, delta } => {
                let entry = self
                    .state
                    .entry(String::from(key))
                    .or_insert_with(|| CrdtValue::Counter(BTreeMap::new()));
                if let CrdtValue::Counter(counts) = entry {
                    *counts.entry(node).or_insert(0) += delta;
                }
            }
            CrdtOp::Set { value, clock, lww } => {
                let entry = self.state.entry(String::from(key)).or_insert(CrdtValue::Register {
                    value: Vec::new(),
                    clock: VectorClock::new(),
                    lww: LwwMetadata {
                        timestamp: 0,
                        node_id: NodeId(0),
                        value_hash: [0u8; 32],
                    },
                });
                if let CrdtValue::Register { value: old_value, clock: old_clock, lww: old_lww } =
                    entry
                {
                    if old_clock.happens_before(&clock) {
                        *old_value = value;
                        *old_clock = clock;
                        *old_lww = lww.clone();
                        self.audit.push(MergeAudit::Accepted {
                            key: key.to_owned(),
                            timestamp: lww.timestamp,
                            node_id: lww.node_id.0,
                        });
                    } else if clock.happens_before(old_clock) {
                        // Existing wins
                        self.audit
                            .push(MergeAudit::RejectedOlder { key: key.to_owned() });
                    } else if old_clock.is_concurrent_with(&clock) {
                        // BC-34: детерминированный tie-break по каноническим полям
                        let by = tie_break_reason(old_lww, &lww);
                        if is_new_lww_winner(old_lww, &lww) {
                            *old_value = value;
                            *old_clock = clock;
                            *old_lww = lww.clone();
                            self.audit.push(MergeAudit::ConcurrentTieBreak {
                                key: key.to_owned(),
                                winner_node: lww.node_id.0,
                                winner_ts: lww.timestamp,
                                by,
                            });
                        } else {
                            self.audit.push(MergeAudit::ConcurrentTieBreak {
                                key: key.to_owned(),
                                winner_node: old_lww.node_id.0,
                                winner_ts: old_lww.timestamp,
                                by,
                            });
                        }
                    } else if old_clock == &clock {
                        if is_new_lww_winner(old_lww, &lww) {
                            *old_value = value;
                            *old_lww = lww.clone();
                            self.audit.push(MergeAudit::Accepted {
                                key: key.to_owned(),
                                timestamp: lww.timestamp,
                                node_id: lww.node_id.0,
                            });
                        } else {
                            self.audit.push(MergeAudit::RejectedOlder { key: key.to_owned() });
                        }
                    } else {
                        // равные часы и равные lww — идемпотентно
                        self.audit
                            .push(MergeAudit::RejectedOlder { key: key.to_owned() });
                    }
                }
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&CrdtValue> {
        self.state.get(key)
    }

    pub fn register_value(&self, key: &str) -> Option<&[u8]> {
        match self.state.get(key) {
            Some(CrdtValue::Register { value, .. }) => Some(value),
            _ => None,
        }
    }

    pub fn counter_total(&self, key: &str) -> u64 {
        match self.state.get(key) {
            Some(CrdtValue::Counter(c)) => c.values().sum(),
            _ => 0,
        }
    }

    /// Журнал аудит-событий merge (для L7 Observability).
    pub fn audit(&self) -> &[MergeAudit] {
        &self.audit
    }

    pub fn drain_audit(&mut self) -> Vec<MergeAudit> {
        std::mem::take(&mut self.audit)
    }

    /// Детерминированный отпечаток состояния (Стрибог-256 по canonical CBOR)
    /// — проверка конвергенции реплик.
    pub fn state_hash(&self) -> [u8; 32] {
        streebog256(&self.state_cbor().to_vec())
    }

    pub fn state_cbor(&self) -> Cbor {
        let items: Vec<Cbor> = self
            .state
            .iter()
            .map(|(k, v)| {
                let vc = match v {
                    CrdtValue::Counter(counts) => Cbor::map(vec![
                        (Cbor::text("t"), Cbor::text("counter")),
                        (
                            Cbor::text("counts"),
                            Cbor::map(
                                counts.iter().map(|(n, c)| (Cbor::UInt(n.0), Cbor::UInt(*c))).collect::<Vec<_>>(),
                            ),
                        ),
                    ]),
                    CrdtValue::Register { value, clock, lww } => Cbor::map(vec![
                        (Cbor::text("t"), Cbor::text("register")),
                        (Cbor::text("value"), Cbor::bytes(value.clone())),
                        (Cbor::text("clock"), clock.to_cbor()),
                        (Cbor::text("lww"), lww.to_cbor()),
                    ]),
                };
                Cbor::map(vec![(Cbor::text("key"), Cbor::text(k.clone())), (Cbor::text("v"), vc)])
            })
            .collect();
        Cbor::array(items)
    }

    /// Передача состояния (state transfer для SYNC/RECOVERY, §13.16.4).
    pub fn merge_state_snapshot(&mut self, snapshot: &Cbor) -> Result<(), ()> {
        let arr = snapshot.as_array().ok_or(())?;
        for item in arr {
            let key = item.get("key").and_then(|v| v.as_text()).ok_or(())?.to_owned();
            let v = item.get("v").ok_or(())?;
            match v.get("t").and_then(|x| x.as_text()) {
                Some("counter") => {
                    let mut counts = BTreeMap::new();
                    if let Cbor::Map(items) = v.get("counts").ok_or(())? {
                        for (k, c) in items {
                            counts.insert(NodeId(k.as_u64().ok_or(())?), c.as_u64().ok_or(())?);
                        }
                    }
                    let entry = self
                        .state
                        .entry(key)
                        .or_insert_with(|| CrdtValue::Counter(BTreeMap::new()));
                    if let CrdtValue::Counter(existing) = entry {
                        for (n, c) in counts {
                            // G-counter merge: max по каждому узлу (идемпотентно)
                            let e = existing.entry(n).or_insert(0);
                            *e = (*e).max(c);
                        }
                    }
                }
                Some("register") => {
                    let value = v.get("value").and_then(|x| x.as_bytes()).ok_or(())?.to_vec();
                    let clock = VectorClock::from_cbor(v.get("clock").ok_or(())?).ok_or(())?;
                    let lww = LwwMetadata::from_cbor(v.get("lww").ok_or(())?).ok_or(())?;
                    self.apply(&key, CrdtOp::Set { value, clock, lww });
                }
                _ => return Err(()),
            }
        }
        Ok(())
    }
}

/// Причина tie-break для аудита (canonical fields: timestamp → node_id →
/// value_hash, BC-34).
fn tie_break_reason(old: &LwwMetadata, new: &LwwMetadata) -> &'static str {
    if new.timestamp != old.timestamp {
        "timestamp"
    } else if new.node_id != old.node_id {
        "node_id"
    } else {
        "value_hash"
    }
}

fn is_new_lww_winner(old: &LwwMetadata, new: &LwwMetadata) -> bool {
    if new.timestamp != old.timestamp {
        return new.timestamp > old.timestamp;
    }
    if new.node_id != old.node_id {
        return new.node_id > old.node_id;
    }
    new.value_hash > old.value_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(entries: &[(u64, u64)]) -> VectorClock {
        VectorClock(entries.iter().map(|(n, v)| (NodeId(*n), *v)).collect())
    }

    #[test]
    fn happens_before_canonical_c06() {
        // объединение ключей: {A:1} < {A:1,B:1}
        let c1 = clock(&[(1, 1)]);
        let c2 = clock(&[(1, 1), (2, 1)]);
        assert!(c1.happens_before(&c2));
        assert!(!c2.happens_before(&c1));
        assert!(c1.is_concurrent_with(&clock(&[(2, 1)])));
        // равные — не concurrent и не before
        assert!(!c1.happens_before(&clock(&[(1, 1)])));
        assert!(!c1.is_concurrent_with(&clock(&[(1, 1)])));
        // {A:2,B:1} vs {A:1,B:2} — concurrent
        assert!(clock(&[(1, 2), (2, 1)]).is_concurrent_with(&clock(&[(1, 1), (2, 2)])));
    }

    #[test]
    fn tie_break_order_bc34() {
        // timestamp важнее node_id, node_id важнее value_hash
        let lo = LwwMetadata { timestamp: 10, node_id: NodeId(5), value_hash: [0xFF; 32] };
        let hi_ts = LwwMetadata { timestamp: 11, node_id: NodeId(1), value_hash: [0x00; 32] };
        assert!(is_new_lww_winner(&lo, &hi_ts), "большой timestamp побеждает");
        let a = LwwMetadata { timestamp: 7, node_id: NodeId(2), value_hash: [0xFF; 32] };
        let b = LwwMetadata { timestamp: 7, node_id: NodeId(3), value_hash: [0x00; 32] };
        assert!(is_new_lww_winner(&a, &b), "большой node_id побеждает");
        let x = LwwMetadata { timestamp: 7, node_id: NodeId(2), value_hash: [0x01; 32] };
        let y = LwwMetadata { timestamp: 7, node_id: NodeId(2), value_hash: [0x02; 32] };
        assert!(is_new_lww_winner(&x, &y), "большой value_hash побеждает");
        // антисимметричность
        assert!(!is_new_lww_winner(&y, &x));
    }

    #[test]
    fn concurrent_sets_converge_deterministically() {
        // два узла независимо пишут один ключ (concurrent) — порядок
        // применения НЕ влияет на результат (nondeterministic discard запрещён)
        let c_a = clock(&[(1, 1)]);
        let c_b = clock(&[(2, 1)]);
        let op_a = CrdtOp::Set {
            value: b"from-A".to_vec(),
            clock: c_a.clone(),
            lww: LwwMetadata::new(100, NodeId(1), b"from-A"),
        };
        let op_b = CrdtOp::Set {
            value: b"from-B".to_vec(),
            clock: c_b.clone(),
            lww: LwwMetadata::new(100, NodeId(2), b"from-B"),
        };
        let mut e1 = CrdtEngine::new();
        e1.apply("k", op_a.clone());
        e1.apply("k", op_b.clone());
        let mut e2 = CrdtEngine::new();
        e2.apply("k", op_b.clone());
        e2.apply("k", op_a.clone());
        assert_eq!(e1.register_value("k"), e2.register_value("k"));
        assert_eq!(e1.state_hash(), e2.state_hash());
        // победитель — node_id 2 (timestamps равны)
        assert_eq!(e1.register_value("k"), Some(&b"from-B"[..]));
        assert_eq!(e2.register_value("k"), Some(&b"from-B"[..]));
        // audit event сопровождает merge (CRDT-REG-001)
        assert!(e1.audit().iter().any(|a| matches!(
            a,
            MergeAudit::ConcurrentTieBreak { winner_node: 2, by: "node_id", .. }
        )));
    }

    #[test]
    fn causal_update_wins_over_concurrent_tie() {
        // более поздний по часам (causal) выигрывает даже с меньшим node_id
        let older = CrdtOp::Set {
            value: b"old".to_vec(),
            clock: clock(&[(1, 1)]),
            lww: LwwMetadata::new(50, NodeId(9), b"old"),
        };
        let newer = CrdtOp::Set {
            value: b"new".to_vec(),
            clock: clock(&[(1, 1), (2, 1)]),
            lww: LwwMetadata::new(50, NodeId(2), b"new"),
        };
        let mut e = CrdtEngine::new();
        e.apply("k", newer.clone());
        e.apply("k", older.clone()); // причинно более старое — отклоняется
        assert_eq!(e.register_value("k"), Some(&b"new"[..]));
        let mut e2 = CrdtEngine::new();
        e2.apply("k", older);
        e2.apply("k", newer);
        assert_eq!(e2.register_value("k"), Some(&b"new"[..]));
        assert_eq!(e.state_hash(), e2.state_hash());
    }

    #[test]
    fn counters_merge_idempotent() {
        let mut e1 = CrdtEngine::new();
        let mut e2 = CrdtEngine::new();
        e1.apply("c", CrdtOp::Increment { node: NodeId(1), delta: 3 });
        e2.apply("c", CrdtOp::Increment { node: NodeId(2), delta: 5 });
        assert_eq!(e1.counter_total("c"), 3);
        assert_eq!(e2.counter_total("c"), 5);
        // state transfer: e1 получает снапшот e2 (и наоборот) — max-merge
        e1.merge_state_snapshot(&e2.state_cbor()).unwrap();
        e2.merge_state_snapshot(&e1.state_cbor()).unwrap();
        assert_eq!(e1.counter_total("c"), 8);
        assert_eq!(e2.counter_total("c"), 8);
        // идемпотентность повторного снапшота
        e1.merge_state_snapshot(&e2.state_cbor()).unwrap();
        assert_eq!(e1.counter_total("c"), 8);
    }

    #[test]
    fn op_serialization_roundtrip() {
        let op = CrdtOp::Set {
            value: b"payload".to_vec(),
            clock: clock(&[(3, 7)]),
            lww: LwwMetadata::new(42, NodeId(3), b"payload"),
        };
        let enc = op.to_cbor(1).to_vec();
        let dec = CrdtOp::from_cbor(&Cbor::from_slice(&enc).unwrap()).unwrap();
        match dec {
            CrdtOp::Set { value, clock, lww } => {
                assert_eq!(value, b"payload");
                assert_eq!(clock, clock_(&[(3, 7)]));
                assert_eq!(lww.timestamp, 42);
            }
            _ => panic!(),
        }
        let inc = CrdtOp::Increment { node: NodeId(2), delta: 9 };
        let enc2 = inc.to_cbor(1).to_vec();
        match CrdtOp::from_cbor(&Cbor::from_slice(&enc2).unwrap()).unwrap() {
            CrdtOp::Increment { node, delta } => {
                assert_eq!(node, NodeId(2));
                assert_eq!(delta, 9);
            }
            _ => panic!(),
        }
    }

    fn clock_(entries: &[(u64, u64)]) -> VectorClock {
        clock(entries)
    }

    /// Свойство: произвольные перестановки одного набора операций дают
    /// идентичное состояние (property-based, §21.7).
    #[test]
    fn permutation_convergence_property() {
        let ops: Vec<(String, CrdtOp)> = vec![
            ("a".into(), CrdtOp::Set { value: b"v1".to_vec(), clock: clock(&[(1, 1)]), lww: LwwMetadata::new(10, NodeId(1), b"v1") }),
            ("a".into(), CrdtOp::Set { value: b"v2".to_vec(), clock: clock(&[(2, 1)]), lww: LwwMetadata::new(10, NodeId(2), b"v2") }),
            ("a".into(), CrdtOp::Set { value: b"v3".to_vec(), clock: clock(&[(1, 1), (2, 1)]), lww: LwwMetadata::new(11, NodeId(1), b"v3") }),
            ("b".into(), CrdtOp::Increment { node: NodeId(1), delta: 1 }),
            ("b".into(), CrdtOp::Increment { node: NodeId(2), delta: 2 }),
        ];
        // несколько псевдослучайных перестановок (детерминированный LCG)
        let mut seed: u64 = 0x2545F4914F6CDD1D;
        let mut hashes = Vec::new();
        for _ in 0..12 {
            let mut idx: Vec<usize> = (0..ops.len()).collect();
            for i in (1..idx.len()).rev() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let j = ((seed >> 33) as usize) % (i + 1);
                idx.swap(i, j);
            }
            let mut e = CrdtEngine::new();
            for i in idx {
                e.apply(&ops[i].0, ops[i].1.clone());
            }
            hashes.push(e.state_hash());
        }
        assert!(hashes.iter().all(|h| h == &hashes[0]), "все перестановки сходятся");
    }
}
