//! Интеграционные испытания платформы (§15.4, SAKURA.TEST.*):
//! «кластер в процессе» — 4 узла, реальные NPP-кадры с RS(544,514) FEC,
//! гибридная криптография (ГОСТ+ML-DSA), SakuraBFT, CRDT-конвергенция,
//! hash-chain аудит. Сценарии: финализация, отказ proposer'а → view change,
//! партиция → ISOLATED → heal → SYNC, коррекция битовых ошибок FEC,
//! equivocation → QUARANTINE.

use sakura_common::cbor::Cbor;
use sakura_consensus::engine::{Engine, Event, FsmState, Msg, PHASE_COMMIT, PHASE_PREPARE};
use sakura_consensus::node::{BftNode, Block, ConsensusError, SignatureVerifier, Vote};
use sakura_crdt::{CrdtEngine, CrdtOp, LwwMetadata, NodeId, VectorClock};
use sakura_hybrid::{hybrid_sign, hybrid_verify, HybridKeyPair, HybridPublicKey};
use sakura_npp::frame::{NppCodec, Frame};
use sakura_npp::msg::MsgType;
use sakura_npp::payload::{consensus_wire, TYPE_CONSENSUS_MSG};
use std::collections::HashMap;

// ---------------- крипто-мост консенсуса ----------------

struct HybridVerifier {
    kp: HybridKeyPair,
    registry: HashMap<u32, HybridPublicKey>,
}

impl SignatureVerifier for HybridVerifier {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, ConsensusError> {
        hybrid_sign(&self.kp, msg).map_err(|_| ConsensusError::InvalidSignature)
    }
    fn verify(&self, voter: u32, msg: &[u8], sig: &[u8]) -> bool {
        match self.registry.get(&voter) {
            Some(pk) => hybrid_verify(pk, msg, sig),
            None => false,
        }
    }
}

// ---------------- wire-кодек консенсусных сообщений ----------------

fn encode_msg(m: &Msg) -> Vec<u8> {
    let v = match m {
        Msg::Proposal { block, sig } => Cbor::map(vec![
            (Cbor::text("m"), Cbor::text("proposal")),
            (
                Cbor::text("block"),
                consensus_wire::block_to_cbor(block.height, block.view, &block.parent_hash, &block.payload, block.proposer),
            ),
            (Cbor::text("sig"), Cbor::bytes(sig.clone())),
        ]),
        Msg::PrepareVote(vote) => vote_wire("prepare", vote),
        Msg::CommitVote(vote) => vote_wire("commit", vote),
        Msg::ViewChangeReq { view, node, sig } => {
            consensus_wire::viewchange_to_cbor("vcreq", *view, *node, sig)
        }
        Msg::NewViewAnnounce { view, node, sig } => {
            consensus_wire::viewchange_to_cbor("newview", *view, *node, sig)
        }
        Msg::SyncRequest { node, height } => {
            consensus_wire::sync_to_cbor("syncreq", *node, *height, &[], &[])
        }
        Msg::SyncResponse { node, height, finalized, blocks } => {
            let bc: Vec<Cbor> = blocks
                .iter()
                .map(|b| consensus_wire::block_to_cbor(b.height, b.view, &b.parent_hash, &b.payload, b.proposer))
                .collect();
            consensus_wire::sync_to_cbor("syncresp", *node, *height, finalized, &bc)
        }
        Msg::Alive { node } => Cbor::map(vec![
            (Cbor::text("m"), Cbor::text("alive")),
            (Cbor::text("node"), Cbor::UInt(*node as u64)),
        ]),
    };
    v.to_vec()
}

fn vote_wire(kind: &str, v: &Vote) -> Cbor {
    Cbor::map(vec![
        (Cbor::text("m"), Cbor::text(kind)),
        (
            Cbor::text("vote"),
            consensus_wire::vote_to_cbor(
                &v.block_hash,
                v.voter,
                v.view,
                if kind == "prepare" { PHASE_PREPARE } else { PHASE_COMMIT },
                &v.signature,
            ),
        ),
    ])
}

fn decode_msg(payload: &[u8]) -> Option<Msg> {
    let v = Cbor::from_slice(payload).ok()?;
    let kind = v
        .get("m")
        .and_then(|x| x.as_text())
        .or_else(|| v.get("kind").and_then(|x| x.as_text()))?;
    match kind {
        "proposal" => {
            let (height, view, parent, pl, proposer) = consensus_wire::block_from_cbor(v.get("block")?)?;
            Some(Msg::Proposal {
                block: Block { height, view, parent_hash: parent, payload: pl, proposer },
                sig: v.get("sig")?.as_bytes()?.to_vec(),
            })
        }
        "prepare" | "commit" => {
            let (bh, voter, view, phase, sig) = consensus_wire::vote_from_cbor(v.get("vote")?)?;
            let vote = Vote { block_hash: bh, voter, view, signature: sig };
            if phase == PHASE_PREPARE {
                Some(Msg::PrepareVote(vote))
            } else {
                Some(Msg::CommitVote(vote))
            }
        }
        "vcreq" | "newview" => {
            let (kind, view, node, sig) = consensus_wire::viewchange_from_cbor(&v)?;
            if kind == "vcreq" {
                Some(Msg::ViewChangeReq { view, node, sig })
            } else {
                Some(Msg::NewViewAnnounce { view, node, sig })
            }
        }
        "syncreq" => {
            let (_, node, height, _, _) = consensus_wire::sync_from_cbor(&v)?;
            Some(Msg::SyncRequest { node, height })
        }
        "syncresp" => {
            let (_, node, height, finalized, block_cbs) = consensus_wire::sync_from_cbor(&v)?;
            let mut blocks = Vec::new();
            for bc in &block_cbs {
                let (h, view, parent, pl, proposer) = consensus_wire::block_from_cbor(bc)?;
                blocks.push(Block { height: h, view, parent_hash: parent, payload: pl, proposer });
            }
            Some(Msg::SyncResponse { node, height, finalized, blocks })
        }
        "alive" => Some(Msg::Alive { node: v.get("node")?.as_u64()? as u32 }),
        _ => None,
    }
}

// ---------------- тестовый узел ----------------

struct TNode {
    engine: Engine,
    crdt: CrdtEngine,
    audit: Vec<(String, [u8; 32])>, // (event, hash) — упрощённый журнал
    codec: NppCodec,
    frames_rx: u64,
    frames_tx: u64,
    fec_corrected: u64,
}

impl TNode {
    fn new(id: u32, n: u32, registry: HashMap<u32, HybridPublicKey>, kp: HybridKeyPair) -> Self {
        let verifier = Box::new(HybridVerifier { kp, registry });
        let mut engine = Engine::new(BftNode::new(id, n, verifier));
        engine.set_timeouts(400);
        let mut ev = Vec::new();
        engine.start(&mut ev);
        TNode {
            engine,
            crdt: CrdtEngine::new(),
            audit: Vec::new(),
            codec: NppCodec::new(true), // FEC RS(544,514) включён
            frames_rx: 0,
            frames_tx: 0,
            fec_corrected: 0,
        }
    }

    fn apply_finalized(&mut self, block: &Block) {
        let Ok(v) = Cbor::from_slice(&block.payload) else { return };
        let Some(ops) = v.as_array() else { return };
        for op in ops {
            let key = op.get("key").and_then(|k| k.as_text()).unwrap_or("").to_owned();
            if let Some(opc) = op.get("op") {
                if let Some(cop) = CrdtOp::from_cbor(opc) {
                    self.crdt.apply(&key, cop);
                }
            }
        }
        self.audit.push((
            "CONSENSUS_FINALIZATION".into(),
            sakura_gost::hash::streebog256(&block.hash()),
        ));
    }
}

// ---------------- тестовая сеть (NPP-кадры) ----------------

struct TNet {
    nodes: Vec<TNode>,
    down: Vec<bool>,
    /// Реассемблеры фрагментов по принимающим узлам.
    reasm: Vec<sakura_npp::frame::FrameReassembler>,
}

impl TNet {
    fn new(n: u32) -> (TNet, Vec<HybridKeyPair>) {
        let kps: Vec<HybridKeyPair> = (0..n).map(|_| HybridKeyPair::generate().unwrap()).collect();
        let mut registry = HashMap::new();
        for (i, kp) in kps.iter().enumerate() {
            registry.insert(i as u32, kp.public.clone());
        }
        let nodes = (0..n)
            .map(|i| TNode::new(i, n, registry.clone(), clone_kp(&kps[i as usize])))
            .collect();
        let reasm = (0..n).map(|_| sakura_npp::frame::FrameReassembler::new()).collect();
        (TNet { nodes, down: vec![false; n as usize], reasm }, kps)
    }

    /// Кадрная доставка одного сообщения от src всем живым (реальный
    /// NPP-кодек: preamble/CRC8/padding/FEC RS(544,514)/CRC32 + MGM-плоскость
    /// опущена как в узле — шифрование тестируется в crypto-модулях).
    fn frame_deliver(&mut self, src: usize, mtype: u8, payload: &[u8], corrupt_bit: Option<usize>) -> Vec<(usize, Msg)> {
        // фрагментация (§13.3): консенсус-сообщения с гибридными подписями
        // (3373 Б) требуют нескольких кадров
        let frags = sakura_npp::frame::split_fragments(payload);
        let multi = frags.len() > 1;
        let mut out = Vec::new();
        for frag in frags {
            let mut flags = 0u8;
            if multi {
                flags |= sakura_npp::frame::FLAG_FRAGMENT;
            }
            self.nodes[src].frames_tx += 1;
            let seq = (self.nodes[src].frames_tx % 65535) as u32;
            let frame = Frame {
                src: src as u16,
                dst: 0xFFFF,
                seq,
                msg_type: MsgType::from_u8(mtype).unwrap_or(MsgType::Status),
                flags,
                payload: frag,
            };
            let mut wire = self.nodes[src].codec.encode(&frame).expect("encode");
            if let Some(bit) = corrupt_bit {
                // повреждение в области данных (за header) — проверяем FEC
                let byte = 9 + (bit / 8) % (wire.len().saturating_sub(13)).max(1);
                wire[byte] ^= 1 << (bit % 8);
            }
            for i in 0..self.nodes.len() {
                if i == src || self.down[i] {
                    continue;
                }
                let decoded = {
                    let node = &mut self.nodes[i];
                    match node.codec.decode(&wire) {
                        Ok(d) => {
                            node.frames_rx += 1;
                            if d.used_fec_correction() {
                                node.fec_corrected += 1;
                            }
                            Some(d)
                        }
                        Err(_) => None,
                    }
                };
                let Some(decoded) = decoded else { continue };
                let f = decoded.frame;
                let plain = if f.flags & sakura_npp::frame::FLAG_FRAGMENT != 0 {
                    match self.reasm[i].push(f.src, mtype, &f.payload, 0) {
                        Ok(Some(full)) => full,
                        _ => continue,
                    }
                } else {
                    f.payload.clone()
                };
                if let Some(m) = decode_msg(&plain) {
                    out.push((i, m));
                }
            }
        }
        out
    }

    fn broadcast(&mut self, src: usize, m: &Msg) {
        let payload = encode_msg(m);
        let delivered = self.frame_deliver(src, TYPE_CONSENSUS_MSG, &payload, None);
        let mut queue: Vec<(usize, Msg)> = delivered;
        let mut rounds = 0;
        while !queue.is_empty() && rounds < 80 {
            rounds += 1;
            let mut next = Vec::new();
            for (dst, msg) in queue.drain(..) {
                let mut ev = Vec::new();
                let tx = {
                    let node = &mut self.nodes[dst];
                    node.engine.on_msg(&msg, &mut ev)
                };
                self.collect_events(dst, ev);
                for t in tx {
                    let p = encode_msg(&t);
                    let d = self.frame_deliver(dst, TYPE_CONSENSUS_MSG, &p, None);
                    next.extend(d);
                }
            }
            queue = next;
        }
    }

    fn collect_events(&mut self, idx: usize, events: Vec<Event>) {
        for e in events {
            match e {
                Event::Finalized { .. } => {
                    let block = self.nodes[idx].engine.finalized_log().last().map(|(_, _, b)| b.clone());
                    if let Some(b) = block {
                        self.nodes[idx].apply_finalized(&b);
                    }
                }
                Event::SyncApply(block) => {
                    self.nodes[idx].apply_finalized(&block);
                }
                _ => {}
            }
        }
    }

    fn propose(&mut self, ops: Vec<(String, CrdtOp)>) {
        let proposer = (0..self.nodes.len())
            .find(|&i| !self.down[i] && self.nodes[i].engine.is_proposer());
        let Some(p) = proposer else { return };
        let block_ops: Vec<Cbor> = ops
            .into_iter()
            .map(|(key, op)| {
                Cbor::map(vec![
                    (Cbor::text("key"), Cbor::text(key)),
                    (Cbor::text("op"), op.to_cbor(1)),
                ])
            })
            .collect();
        let payload = Cbor::array(block_ops).to_vec();
        let mut ev = Vec::new();
        let msgs = self.nodes[p].engine.propose(payload, &mut ev).unwrap();
        self.collect_events(p, ev);
        for m in msgs {
            self.broadcast(p, &m);
        }
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.engine.height()).collect()
    }

    fn tick_all(&mut self, now: u64) {
        let mut queue: Vec<(usize, Msg)> = Vec::new();
        for i in 0..self.nodes.len() {
            if self.down[i] {
                continue;
            }
            let mut ev = Vec::new();
            let tx = self.nodes[i].engine.tick_ext(now, &mut ev, true);
            self.collect_events(i, ev);
            for t in tx {
                queue.push((i, t));
            }
        }
        let mut rounds = 0;
        while !queue.is_empty() && rounds < 80 {
            rounds += 1;
            let mut next = Vec::new();
            for (src, m) in queue.drain(..) {
                let p = encode_msg(&m);
                let delivered = self.frame_deliver(src, TYPE_CONSENSUS_MSG, &p, None);
                for (dst, msg) in delivered {
                    let mut ev = Vec::new();
                    let tx = {
                        let node = &mut self.nodes[dst];
                        node.engine.on_msg(&msg, &mut ev)
                    };
                    self.collect_events(dst, ev);
                    for t in tx {
                        next.push((dst, t));
                    }
                }
            }
            queue = next;
        }
    }

    fn alive_all(&mut self) {
        let mut queue: Vec<(usize, Msg)> = Vec::new();
        for i in 0..self.nodes.len() {
            if !self.down[i] {
                queue.push((i, Msg::Alive { node: i as u32 }));
            }
        }
        let mut rounds = 0;
        while !queue.is_empty() && rounds < 40 {
            rounds += 1;
            let mut next = Vec::new();
            for (src, m) in queue.drain(..) {
                let p = encode_msg(&m);
                let delivered = self.frame_deliver(src, TYPE_CONSENSUS_MSG, &p, None);
                for (dst, msg) in delivered {
                    let mut ev = Vec::new();
                    let tx = {
                        let node = &mut self.nodes[dst];
                        node.engine.on_msg(&msg, &mut ev)
                    };
                    self.collect_events(dst, ev);
                    for t in tx {
                        next.push((dst, t));
                    }
                }
            }
            queue = next;
        }
    }

    fn mark_down(&mut self, idx: usize) {
        self.down[idx] = true;
        for i in 0..self.nodes.len() {
            if i != idx && !self.down[i] {
                let mut ev = Vec::new();
                self.nodes[i].engine.note_peer_down(idx as u32, &mut ev);
                self.collect_events(i, ev);
            }
        }
    }

    fn mark_up(&mut self, idx: usize) {
        self.down[idx] = false;
    }
}

fn clone_kp(kp: &HybridKeyPair) -> HybridKeyPair {
    HybridKeyPair {
        gost_priv: kp.gost_priv,
        mldsa_sk: kp.mldsa_sk.clone(),
        mlkem_dk: kp.mlkem_dk.clone(),
        public: HybridPublicKey::from_bytes(&kp.public.to_bytes()).unwrap(),
    }
}

fn kv_op(node: u64, ts: u64, value: &[u8]) -> CrdtOp {
    let mut clock = VectorClock::new();
    clock.increment(NodeId(node));
    CrdtOp::Set {
        value: value.to_vec(),
        clock,
        lww: LwwMetadata::new(ts, NodeId(node), value),
    }
}

// ==================== СЦЕНАРИИ (§15.4) ====================

/// SAKURA.TEST.BFT.001: финализация блока и CRDT-конвергенция по реальным
/// NPP-кадрам с FEC.
#[test]
fn cluster_finalization_over_npp_frames() {
    let (mut net, _kps) = TNet::new(4);
    net.alive_all();
    net.propose(vec![("sensor.temp".into(), kv_op(1, 100, b"21.5"))]);
    assert_eq!(net.heights(), vec![1, 1, 1, 1], "все узлы финализировали блок 0");
    net.propose(vec![
        ("config.mode".into(), kv_op(1, 101, b"production")),
        ("counter.hits".into(), CrdtOp::Increment { node: NodeId(2), delta: 7 }),
    ]);
    assert_eq!(net.heights(), vec![2, 2, 2, 2]);
    // CRDT-конвергенция: идентичные state hash на всех узлах
    let hashes: Vec<[u8; 32]> = net.nodes.iter().map(|n| n.crdt.state_hash()).collect();
    assert!(hashes.iter().all(|h| h == &hashes[0]), "CRDT converged");
    assert_eq!(net.nodes[0].crdt.register_value("sensor.temp"), Some(&b"21.5"[..]));
    assert_eq!(net.nodes[3].crdt.counter_total("counter.hits"), 7);
    // кадры реально ходили через NPP-кодек
    assert!(net.nodes[0].frames_tx > 0 && net.nodes[1].frames_rx > 0);
    // аудит финализаций ведётся на каждом узле
    for n in &net.nodes {
        assert_eq!(n.audit.len(), 2);
        assert_eq!(n.audit[0].0, "CONSENSUS_FINALIZATION");
    }
}

/// SAKURA.TEST.BFT.002: FEC исправляет битовые ошибки канала — блок
/// финализируется несмотря на повреждение кадров (≤ t=15 символов).
#[test]
fn fec_recovers_line_errors() {
    let (mut net, _kps) = TNet::new(4);
    net.alive_all();
    // предложим блок и вручную исказим каждый доставляемый кадр (1 бит)
    let proposer = (0..4).find(|&i| net.nodes[i].engine.is_proposer()).unwrap();
    let ops = Cbor::array(vec![Cbor::map(vec![
        (Cbor::text("key"), Cbor::text("k")),
        (Cbor::text("op"), kv_op(1, 5, b"v").to_cbor(1)),
    ])])
    .to_vec();
    let mut ev = Vec::new();
    let msgs = net.nodes[proposer].engine.propose(ops, &mut ev).unwrap();
    net.collect_events(proposer, ev);
    for m in msgs {
        let payload = encode_msg(&m);
        let delivered = net.frame_deliver(proposer, TYPE_CONSENSUS_MSG, &payload, Some(3));
        let mut queue = delivered;
        let mut rounds = 0;
        while !queue.is_empty() && rounds < 80 {
            rounds += 1;
            let mut next = Vec::new();
            for (dst, msg) in queue.drain(..) {
                let mut ev = Vec::new();
                let tx = {
                    let node = &mut net.nodes[dst];
                    node.engine.on_msg(&msg, &mut ev)
                };
                net.collect_events(dst, ev);
                for t in tx {
                    let p = encode_msg(&t);
                    let d = net.frame_deliver(dst, TYPE_CONSENSUS_MSG, &p, Some(7));
                    next.extend(d);
                }
            }
            queue = next;
        }
    }
    assert_eq!(net.heights(), vec![1, 1, 1, 1], "финализация несмотря на битовые ошибки");
    let corrected: u64 = net.nodes.iter().map(|n| n.fec_corrected).sum();
    assert!(corrected > 0, "FEC реально исправлял ошибки (символов: {corrected})");
}

/// SAKURA.TEST.BFT.003: отказ proposer'а → VIEW_CHANGE → новый proposer
/// финализирует (CONS-004, CONS-LAT-004).
#[test]
fn proposer_failure_view_change() {
    let (mut net, _kps) = TNet::new(4);
    net.alive_all();
    // proposer view 0 = node0 — «умирает»
    net.mark_down(0);
    let now = sakura_common::time::unix_ms() + 2_000;
    net.tick_all(now);
    for i in 1..4 {
        assert!(net.nodes[i].engine.view() >= 1, "view сменилась у узла {i}");
    }
    // новый proposer финализирует блок
    net.propose(vec![("after.failover".into(), kv_op(2, 200, b"ok"))]);
    for i in 1..4 {
        assert_eq!(net.nodes[i].engine.height(), 1, "узел {i} финализировал");
    }
    assert_eq!(net.nodes[1].crdt.register_value("after.failover"), Some(&b"ok"[..]));
}

/// SAKURA.TEST.BFT.004: партиция → кворум потерян → ISOLATED; heal →
/// SYNC/RECOVERY → догоняет историю (CONS-007, §13.16.4, REL-005).
#[test]
fn partition_isolated_and_state_sync() {
    let (mut net, _kps) = TNet::new(4);
    net.alive_all();
    net.propose(vec![("k1".into(), kv_op(1, 10, b"a"))]);
    assert_eq!(net.heights(), vec![1, 1, 1, 1]);
    // node3 изолирован: не слышит остальных
    net.mark_down(3);
    // у node3 peers «молчат» (heartbeat timeout) → ISOLATED
    {
        let mut ev = Vec::new();
        for i in 0..3u32 {
            net.nodes[3].engine.note_peer_down(i, &mut ev);
        }
        net.collect_events(3, ev);
    }
    assert_eq!(net.nodes[3].engine.state, FsmState::Isolated, "меньшинство — ISOLATED");
    assert_eq!(net.nodes[0].engine.state, FsmState::Degraded, "большинство — DEGRADED");
    // большинство продолжает финализацию без node3
    net.propose(vec![("k2".into(), kv_op(1, 11, b"b"))]);
    assert_eq!(net.nodes[0].engine.height(), 2);
    assert_eq!(net.nodes[3].engine.height(), 1, "изолированный отстал");
    // heal: node3 снова слышит всех
    net.mark_up(3);
    net.alive_all(); // Alive-обмен → ISOLATED? node3 был Degraded? (он down-ом не получал Alive)
    // node3: получает Alive от 0,1,2 → quorum → SYNC → SyncRequest/Response
    // → импорт блока 1 → RecoveryDone
    let now = sakura_common::time::unix_ms();
    net.tick_all(now);
    // доставим sync-запросы/ответы до схождения
    for _ in 0..3 {
        net.alive_all();
        net.tick_all(sakura_common::time::unix_ms());
    }
    assert_eq!(net.nodes[3].engine.height(), 2, "node3 догнал историю через state transfer");
    assert_eq!(net.nodes[3].crdt.register_value("k2"), Some(&b"b"[..]), "CRDT догнан");
    let hashes: Vec<[u8; 32]> = net.nodes.iter().map(|n| n.crdt.state_hash()).collect();
    assert!(hashes.iter().all(|h| h == &hashes[0]), "конвергенция после heal");
}

/// SAKURA.TEST.BFT.005: equivocation proposer'а → EVIDENCE_LOG +
/// QUARANTINE на всех честных узлах (FV-005).
#[test]
fn equivocation_quarantine_full_stack() {
    let (mut net, kps) = TNet::new(4);
    net.alive_all();
    // node0 — proposer; шлёт блок A всем
    let ops_a = Cbor::array(vec![Cbor::map(vec![
        (Cbor::text("key"), Cbor::text("x")),
        (Cbor::text("op"), kv_op(1, 1, b"A").to_cbor(1)),
    ])])
    .to_vec();
    let mut ev = Vec::new();
    let msgs = net.nodes[0].engine.propose(ops_a, &mut ev).unwrap();
    net.collect_events(0, ev);
    for m in &msgs {
        net.broadcast(0, m);
    }
    // теперь блок B (тот же height/view, другой payload) — напрямую узлам 1..3
    let block_b = Block {
        height: 0,
        view: 0,
        parent_hash: [0u8; 32],
        payload: Cbor::array(vec![Cbor::map(vec![
            (Cbor::text("key"), Cbor::text("x")),
            (Cbor::text("op"), kv_op(1, 1, b"B").to_cbor(1)),
        ])])
        .to_vec(),
        proposer: 0,
    };
    use sakura_consensus::engine::proposal_sign_bytes;
    let sig_b = hybrid_sign(&kps[0], &proposal_sign_bytes(&block_b)).unwrap();
    let wire = Cbor::map(vec![
        (Cbor::text("m"), Cbor::text("proposal")),
        (
            Cbor::text("block"),
            consensus_wire::block_to_cbor(block_b.height, block_b.view, &block_b.parent_hash, &block_b.payload, block_b.proposer),
        ),
        (Cbor::text("sig"), Cbor::bytes(sig_b)),
    ])
    .to_vec();
    let delivered = net.frame_deliver(0, TYPE_CONSENSUS_MSG, &wire, None);
    for (dst, msg) in delivered {
        let mut ev = Vec::new();
        let _ = net.nodes[dst].engine.on_msg(&msg, &mut ev);
        net.collect_events(dst, ev);
    }
    for i in 1..4 {
        assert!(net.nodes[i].engine.quarantine.contains(&0), "узел {i} карантинил эквивокатора");
        assert!(!net.nodes[i].engine.evidence.is_empty(), "узел {i} сохранил evidence");
        let ev = &net.nodes[i].engine.evidence[0];
        assert_ne!(ev.hash_a, ev.hash_b);
        assert_eq!(ev.offender, 0);
    }
}

/// SAKURA.TEST.BFT.006: двойная финализация невозможна на уровне всего
/// стека (FV-003, CONS-006 = 0).
#[test]
fn no_double_finalization_cluster_wide() {
    let (mut net, kps) = TNet::new(4);
    net.alive_all();
    net.propose(vec![("a".into(), kv_op(1, 1, b"1"))]);
    assert_eq!(net.heights(), vec![1, 1, 1, 1]);
    let h0 = net.nodes[0].engine.finalized_hash(0).unwrap();
    // злонамеренный proposer шлёт «альтернативный» блок высоты 0
    let evil = Block {
        height: 0,
        view: 0,
        parent_hash: [0u8; 32],
        payload: b"evil".to_vec(),
        proposer: 0,
    };
    use sakura_consensus::engine::proposal_sign_bytes;
    let sig = hybrid_sign(&kps[0], &proposal_sign_bytes(&evil)).unwrap();
    // даже при доставке голосов финализация невозможна: высота уже занята
    for i in 1..4 {
        let before = net.nodes[i].engine.height();
        let mut ev = Vec::new();
        let _ = net.nodes[i].engine.on_msg(&Msg::Proposal { block: evil.clone(), sig: sig.clone() }, &mut ev);
        net.collect_events(i, ev);
        assert_eq!(net.nodes[i].engine.height(), before);
        assert_eq!(net.nodes[i].engine.finalized_hash(0).unwrap(), h0, "история неизменна");
    }
}
