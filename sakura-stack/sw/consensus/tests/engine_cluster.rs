//! Кластерные испытания Consensus FSM (BC-23): финализация, view change,
//! equivocation → QUARANTINE/EVIDENCE_LOG, partition → DEGRADED/ISOLATED →
//! rejoin → SYNC/RECOVERY. (SAKURA.TEST.BFT.*)

use sakura_common::time::unix_ms;
use sakura_consensus::engine::{vote_sign_bytes, Engine, Event, FsmState, Msg, PHASE_PREPARE};
use sakura_consensus::node::{BftNode, Block, ConsensusError, SignatureVerifier};
use sakura_gost::hash::Hasher256;
use std::collections::HashMap;

/// Тестовый верификатор: «подпись» = Стрибог(secret || msg).
struct TestVerifier {
    id: u32,
    secrets: HashMap<u32, [u8; 8]>,
}

impl SignatureVerifier for TestVerifier {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, ConsensusError> {
        let s = self.secrets.get(&self.id).unwrap();
        let mut h = Hasher256::new();
        h.update(s);
        h.update(msg);
        Ok(h.finalize().to_vec())
    }
    fn verify(&self, voter: u32, msg: &[u8], sig: &[u8]) -> bool {
        match self.secrets.get(&voter) {
            Some(s) => {
                let mut h = Hasher256::new();
                h.update(s);
                h.update(msg);
                h.finalize().as_slice() == sig
            }
            None => false,
        }
    }
}

fn verifier(id: u32) -> Box<dyn SignatureVerifier> {
    let mut secrets = HashMap::new();
    for i in 0..8u32 {
        secrets.insert(i, [i as u8; 8]);
    }
    Box::new(TestVerifier { id, secrets })
}

struct Net {
    engines: Vec<Engine>,
    down: Vec<bool>,
}

impl Net {
    fn new(n: u32) -> Net {
        let engines = (0..n)
            .map(|i| {
                let mut e = Engine::new(BftNode::new(i, n, verifier(i)));
                e.set_timeouts(1_000);
                let mut out = Vec::new();
                e.start(&mut out);
                e
            })
            .collect();
        Net { engines, down: vec![false; n as usize] }
    }

    /// Широковещательный прогон до затишья (не более max_rounds волн).
    fn broadcast(&mut self, from: usize, msg: Msg, events: &mut Vec<(usize, Event)>) {
        let mut queue: Vec<(usize, Msg)> = vec![(from, msg)];
        let mut rounds = 0;
        while !queue.is_empty() && rounds < 64 {
            rounds += 1;
            let mut next = Vec::new();
            for (src, m) in queue.drain(..) {
                for (i, e) in self.engines.iter_mut().enumerate() {
                    if i == src || self.down[i] {
                        continue;
                    }
                    let mut ev = Vec::new();
                    let tx = e.on_msg(&m, &mut ev);
                    events.extend(ev.into_iter().map(|e2| (i, e2)));
                    for t in tx {
                        next.push((i, t));
                    }
                }
            }
            queue = next;
        }
    }

    fn propose_and_run(&mut self, payload: &[u8], events: &mut Vec<(usize, Event)>) {
        // найти proposer'а текущей view среди живых
        let proposer = self
            .engines
            .iter()
            .enumerate()
            .find(|(i, e)| !self.down[*i] && e.is_proposer())
            .map(|(i, _)| i);
        let Some(p) = proposer else { return };
        let mut ev = Vec::new();
        let msgs = self.engines[p].propose(payload.to_vec(), &mut ev).unwrap();
        events.extend(ev.into_iter().map(|e| (p, e)));
        for m in msgs {
            self.broadcast(p, m, events);
        }
    }

    fn finalized(&self, i: usize) -> u64 {
        self.engines[i].height()
    }
}

#[test]
fn cluster_finalizes_block() {
    let mut net = Net::new(4); // f=1, quorum=3
    let mut events = Vec::new();
    net.propose_and_run(b"batch-1", &mut events);
    // все 4 узла финализировали высоту 0
    for i in 0..4 {
        assert_eq!(net.finalized(i), 1, "node {i} finalized");
    }
    // хэши идентичны (детерминированный Стрибог-256)
    let h0 = net.engines[0].finalized_hash(0).unwrap();
    for i in 1..4 {
        assert_eq!(net.engines[i].finalized_hash(0).unwrap(), h0);
    }
    // FSM прошла PREPARE → COMMIT → FINALIZED → BACKUP
    let states: Vec<_> = events.iter().map(|(_, e)| e).collect();
    assert!(states.iter().any(|e| **e == Event::Finalized { height: 0, hash: h0 }));
    assert_eq!(net.engines[0].state, FsmState::Backup);
    // следующая высота
    net.propose_and_run(b"batch-2", &mut events);
    for i in 0..4 {
        assert_eq!(net.finalized(i), 2);
    }
}

#[test]
fn quorum_tolerates_one_byzantine_down() {
    // n=4, f=1: один узел «не отвечает» — кворум 3 всё равно достигается
    let mut net = Net::new(4);
    net.down[3] = true;
    let mut events = Vec::new();
    net.propose_and_run(b"batch-p", &mut events);
    for i in 0..3 {
        assert_eq!(net.finalized(i), 1, "node {i} finalized despite node 3 down");
    }
}

#[test]
fn no_quorum_below_2f_plus_1() {
    // n=4, quorum=3: двое «мертвы» — финализации нет
    let mut net = Net::new(4);
    net.down[2] = true;
    net.down[3] = true;
    let mut events = Vec::new();
    net.propose_and_run(b"batch-q", &mut events);
    for i in 0..2 {
        assert_eq!(net.finalized(i), 0, "no finalization without quorum");
    }
}

#[test]
fn proposer_timeout_triggers_view_change() {
    let mut net = Net::new(4);
    // убить proposer'а view 0 (узел 0)
    net.down[0] = true;
    let mut events = Vec::new();
    // тик у живых узлов: timeout → ViewChangeReq
    let now = unix_ms() + 5_000;
    let mut queue: Vec<(usize, Msg)> = Vec::new();
    for i in 1..4 {
        let mut ev = Vec::new();
        let tx = net.engines[i].tick(now, &mut ev);
        events.extend(ev.into_iter().map(|e| (i, e)));
        for m in tx {
            queue.push((i, m));
        }
    }
    // распространение view-change сообщений
    let mut rounds = 0;
    while !queue.is_empty() && rounds < 32 {
        rounds += 1;
        let mut next = Vec::new();
        for (src, m) in queue.drain(..) {
            for (i, e) in net.engines.iter_mut().enumerate() {
                if i == src || net.down[i] {
                    continue;
                }
                let mut ev = Vec::new();
                let tx = e.on_msg(&m, &mut ev);
                events.extend(ev.into_iter().map(|e2| (i, e2)));
                for t in tx {
                    next.push((i, t));
                }
            }
        }
        queue = next;
    }
    // view стал 1, proposer — узел 1
    for i in 1..4 {
        assert_eq!(net.engines[i].view(), 1, "node {i} moved to view 1");
    }
    assert!(events.iter().any(|(_, e)| *e == Event::ViewChanged(1)));
    // узел 1 (новый proposer) финализирует блок
    net.propose_and_run(b"after-view-change", &mut events);
    for i in 1..4 {
        assert_eq!(net.finalized(i), 1);
    }
}

#[test]
fn equivocation_quarantines_offender() {
    let mut net = Net::new(4);
    // узел 0 — proposer view 0; он «эквивоцирует»: два разных блока
    let mut ev0 = Vec::new();
    let msgs = net.engines[0].propose(b"A".to_vec(), &mut ev0).unwrap();
    let mut events = Vec::new();
    for m in msgs {
        net.broadcast(0, m, &mut events);
    }
    // второе предложение той же (height, view) с другим payload — вручную,
    // подписанное ключом узла 0
    let block_b = Block {
        height: 0,
        view: 0,
        parent_hash: [0u8; 32],
        payload: b"B".to_vec(),
        proposer: 0,
    };
    let sig_b = {
        let mut secrets = HashMap::new();
        for i in 0..8u32 {
            secrets.insert(i, [i as u8; 8]);
        }
        let mut v = TestVerifier { id: 0, secrets };
        v.sign(&sakura_consensus::engine::proposal_sign_bytes(&block_b)).unwrap()
    };
    let mut ev_q = Vec::new();
    for i in 1..4 {
        let tx = net.engines[i].on_msg(&Msg::Proposal { block: block_b.clone(), sig: sig_b.clone() }, &mut ev_q);
        events.extend(ev_q.drain(..).map(|e| (i, e)));
        let _ = tx;
    }
    // все честные узлы заложили evidence и карантинили узел 0
    for i in 1..4 {
        assert!(net.engines[i].quarantine.contains(&0), "node {i} quarantined offender");
        assert!(!net.engines[i].evidence.is_empty(), "node {i} logged evidence");
        let ev = &net.engines[i].evidence[0];
        assert_eq!(ev.offender, 0);
        assert_ne!(ev.hash_a, ev.hash_b);
        assert_eq!(ev.height, 0);
        assert_eq!(ev.view, 0);
    }
    assert!(events.iter().any(|(_, e)| matches!(e, Event::Quarantined(0))));
}

#[test]
fn invalid_proposal_signature_rejected() {
    let mut net = Net::new(4);
    let block = Block {
        height: 0,
        view: 0,
        parent_hash: [0u8; 32],
        payload: b"evil".to_vec(),
        proposer: 0,
    };
    let mut events = Vec::new();
    net.broadcast(0, Msg::Proposal { block, sig: vec![1, 2, 3] }, &mut events);
    // никто не принял блок, у всех evidence о неверной подписи
    for i in 1..4 {
        assert_eq!(net.finalized(i), 0);
        assert!(net.engines[i].current_block().is_none());
    }
    assert!(events.iter().any(|(_, e)| matches!(e, Event::EvidenceLogged { reason, .. } if reason.contains("invalid proposal signature"))));
}

#[test]
fn forged_vote_rejected_and_logged() {
    let mut net = Net::new(4);
    let mut events = Vec::new();
    // честное предложение
    let mut ev0 = Vec::new();
    let msgs = net.engines[0].propose(b"good".to_vec(), &mut ev0).unwrap();
    let block = match &msgs[0] {
        Msg::Proposal { block, .. } => block.clone(),
        _ => panic!(),
    };
    for m in msgs {
        net.broadcast(0, m, &mut events);
    }
    // фальшивый голос от имени узла 3
    let forged = sakura_consensus::node::Vote {
        block_hash: block.hash(),
        voter: 3,
        view: 0,
        signature: vec![9u8; 32],
    };
    let mut ev1 = Vec::new();
    let _ = net.engines[1].on_msg(&Msg::PrepareVote(forged), &mut ev1);
    assert!(ev1.iter().any(|e| matches!(e, Event::EvidenceLogged { offender: 3, .. })));
}

#[test]
fn partition_degraded_isolated_and_rejoin_sync() {
    let mut net = Net::new(4);
    let events: Vec<(usize, Event)> = Vec::new();
    // все видят друг друга (полный обмен Alive + каскад SYNC при необходимости)
    let mut ev_all = Vec::new();
    for i in 0..4u32 {
        net.broadcast(i as usize, Msg::Alive { node: i }, &mut ev_all);
    }
    for (i, e) in net.engines.iter().enumerate() {
        assert_eq!(e.state, FsmState::Backup, "node {i} in Backup after full membership");
    }
    // partition: узел 3 теряет 2 пира → кворум (3) недостижим у него? alive=2 → ISOLATED
    // Узлы 0..2 теряют узел 3 → alive=3 ≥ quorum → DEGRADED
    let mut ev0 = Vec::new();
    net.engines[0].note_peer_down(3, &mut ev0);
    assert_eq!(net.engines[0].state, FsmState::Degraded);
    assert!(ev0.contains(&Event::PartitionDegraded));
    let mut ev3 = Vec::new();
    net.engines[3].note_peer_down(0, &mut ev3);
    net.engines[3].note_peer_down(1, &mut ev3);
    assert_eq!(net.engines[3].state, FsmState::Isolated);
    assert!(ev3.contains(&Event::QuorumLostIsolated));
    // в ISOLATED финализация невозможна (нет кворума) — узел 3 не голосует
    // rejoin: первый же Alive, дающий кворум, переводит узел в SYNC и
    // рассылает SyncRequest (§13.16.4)
    let mut ev3b = Vec::new();
    let mut tx = net.engines[3].on_msg(&Msg::Alive { node: 0 }, &mut ev3b);
    assert_eq!(net.engines[3].state, FsmState::Sync);
    assert!(tx.iter().any(|m| matches!(m, Msg::SyncRequest { .. })));
    assert!(ev3b.contains(&Event::RejoinSync(3)));
    // остальные Alive не сбивают SYNC
    for i in 1..3u32 {
        let m = Msg::Alive { node: i };
        let r = net.engines[3].on_msg(&m, &mut ev3b);
        tx.extend(r);
    }
    assert_eq!(net.engines[3].state, FsmState::Sync);
    // доставить SyncRequest живым узлам, ответы — обратно узлу 3
    let mut responses = Vec::new();
    for m in &tx {
        for (i, e) in net.engines.iter_mut().enumerate() {
            if i == 3 {
                continue;
            }
            let mut ev = Vec::new();
            let r = e.on_msg(m, &mut ev);
            responses.extend(r);
        }
    }
    let mut ev3d = Vec::new();
    for m in &responses {
        let _ = net.engines[3].on_msg(m, &mut ev3d);
    }
    assert_eq!(net.engines[3].state, FsmState::Backup);
    assert!(ev3d.contains(&Event::RecoveryDone));
    let _ = events;
}

#[test]
fn cross_phase_vote_replay_rejected() {
    // голос PREPARE не принимается как COMMIT (phase входит в подпись)
    let mut net = Net::new(4);
    let mut ev0 = Vec::new();
    let msgs = net.engines[0].propose(b"p1".to_vec(), &mut ev0).unwrap();
    let block = match &msgs[0] {
        Msg::Proposal { block, .. } => block.clone(),
        _ => panic!(),
    };
    let mut events = Vec::new();
    for m in msgs {
        net.broadcast(0, m, &mut events);
    }
    // replay: PREPARE-голос узла 1 подставить как COMMIT
    let prepare_bytes = vote_sign_bytes(&block.hash(), 1, 0, PHASE_PREPARE);
    let replay_vote = sakura_consensus::node::Vote {
        block_hash: block.hash(),
        voter: 1,
        view: 0,
        signature: {
            let mut secrets = HashMap::new();
            for i in 0..8u32 {
                secrets.insert(i, [i as u8; 8]);
            }
            let mut v = TestVerifier { id: 1, secrets };
            v.sign(&prepare_bytes).unwrap()
        },
    };
    let mut ev2 = Vec::new();
    let _ = net.engines[2].on_msg(&Msg::CommitVote(replay_vote), &mut ev2);
    // подлог отклонён: evidence о невалидной подписи фазы COMMIT
    assert!(ev2.iter().any(|e| matches!(e, Event::EvidenceLogged { .. })));
}
