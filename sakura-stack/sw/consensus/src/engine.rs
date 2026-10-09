//! Consensus FSM (BC-23 / CONS-FSM-001) — BFT-термины:
//!
//! ```text
//! INIT → BACKUP → on proposal: PREPARE → if quorum prepare: COMMIT
//!   → if quorum commit: FINALIZED → on timeout: VIEW_CHANGE
//!   → if view quorum: NEW_VIEW → if partition: DEGRADED
//!   → if quorum lost: ISOLATED → if rejoin: SYNC/RECOVERY
//!   → if equivocation/byzantine evidence: QUARANTINE/EVIDENCE_LOG
//! ```
//!
//! Нормативные термины candidate/leader из Raft НЕ используются; leader —
//! только как proposer/primary в рамках BFT-протокола (§13.16.4, ICD-1).
//!
//! Двухфазный BFT: PREPARE (кворум 2f+1) → COMMIT (кворум 2f+1) →
//! FINALIZED через референсный узел C-01 (двойная финализация невозможна).

use crate::node::{BftNode, Block, ConsensusError, ConsensusNode, Vote};
use sakura_gost::hash::Hasher256;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsmState {
    Init,
    Backup,
    Prepare,
    Commit,
    Finalized,
    ViewChange,
    NewView,
    Degraded,
    Isolated,
    Sync,
    Recovery,
    Quarantine,
    EvidenceLog,
}

/// Сообщения консенсуса (транспорт — NPP, §13.3).
#[derive(Clone, Debug)]
pub enum Msg {
    /// Предложение блока proposer'ом (фаза PREPARE).
    Proposal { block: Block, sig: Vec<u8> },
    /// Голос PREPARE.
    PrepareVote(Vote),
    /// Голос COMMIT (рассылается после кворума PREPARE).
    CommitVote(Vote),
    /// Запрос смены view (timeout proposer'а).
    ViewChangeReq { view: u64, node: u32, sig: Vec<u8> },
    /// NewView от нового proposer'а (кворум ViewChangeReq собран).
    NewViewAnnounce { view: u64, node: u32, sig: Vec<u8> },
    /// Синхронизация при rejoin (SYNC/RECOVERY).
    SyncRequest { node: u32, height: u64 },
    SyncResponse {
        node: u32,
        height: u64,
        finalized: Vec<(u64, [u8; 32])>,
        /// Финализированные блоки с height ≥ запрошенной (state transfer).
        blocks: Vec<Block>,
    },
    /// Присутствие узла (учёт alive-множества, heartbeat).
    Alive { node: u32 },
}

/// События для узла/аудита (§25.3: consensus finalization — событие журнала).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    EnteredState(FsmState),
    Finalized { height: u64, hash: [u8; 32] },
    EvidenceLogged { offender: u32, reason: String },
    Quarantined(u32),
    ViewChanged(u64),
    PartitionDegraded,
    QuorumLostIsolated,
    RejoinSync(u32),
    RecoveryDone,
    /// Блок применён из state transfer (SYNC/RECOVERY, §13.16.4).
    SyncApply(Block),
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub offender: u32,
    pub height: u64,
    pub view: u64,
    pub hash_a: [u8; 32],
    pub hash_b: [u8; 32],
    pub sig_a: Vec<u8>,
    pub sig_b: Vec<u8>,
}

pub const PHASE_PREPARE: u8 = 1;
pub const PHASE_COMMIT: u8 = 2;
/// CONS-005: MAX_ROUNDS_TO_KEEP = 100.
pub const MAX_ROUNDS_TO_KEEP: usize = 100;

/// Канонические байты для подписи голоса (детерминированный хэш-префикс).
pub fn vote_sign_bytes(block_hash: &[u8; 32], voter: u32, view: u64, phase: u8) -> Vec<u8> {
    let mut h = Hasher256::new();
    h.update(b"SAKURA-VOTE-V1");
    h.update(block_hash);
    h.update(&voter.to_be_bytes());
    h.update(&view.to_be_bytes());
    h.update(&[phase]);
    h.finalize().to_vec()
}

pub fn view_change_sign_bytes(view: u64) -> Vec<u8> {
    let mut h = Hasher256::new();
    h.update(b"SAKURA-VIEWCHANGE-V1");
    h.update(&view.to_be_bytes());
    h.finalize().to_vec()
}

pub fn proposal_sign_bytes(block: &Block) -> Vec<u8> {
    vote_sign_bytes(&block.hash(), block.proposer, block.view, 0)
}

fn now_ms() -> u64 {
    sakura_common::time::unix_ms()
}

pub struct Engine {
    pub node: BftNode,
    pub state: FsmState,
    current: Option<Block>,
    prepares: HashMap<[u8; 32], HashSet<u32>>,
    commits: HashMap<[u8; 32], HashSet<u32>>,
    /// (height, view) → (hash, sig, proposer) — детекция equivocation.
    proposals_seen: HashMap<(u64, u64), ([u8; 32], Vec<u8>, u32)>,
    view_votes: HashMap<u64, HashSet<u32>>,
    alive: HashSet<u32>,
    pub evidence: Vec<Evidence>,
    pub quarantine: HashSet<u32>,
    finalized_log: Vec<(u64, [u8; 32], Block)>,
    last_progress_ms: u64,
    proposer_timeout_ms: u64,
}

impl Engine {
    pub fn new(node: BftNode) -> Self {
        let now = now_ms();
        Engine {
            node,
            state: FsmState::Init,
            current: None,
            prepares: HashMap::new(),
            commits: HashMap::new(),
            proposals_seen: HashMap::new(),
            view_votes: HashMap::new(),
            alive: HashSet::new(),
            evidence: Vec::new(),
            quarantine: HashSet::new(),
            finalized_log: Vec::new(),
            last_progress_ms: now,
            proposer_timeout_ms: 2_000,
        }
    }

    pub fn set_timeouts(&mut self, proposer_timeout_ms: u64) {
        self.proposer_timeout_ms = proposer_timeout_ms;
    }

    pub fn set_clock(&mut self, now: u64) {
        self.last_progress_ms = now;
    }

    fn enter(&mut self, s: FsmState, out: &mut Vec<Event>) {
        if self.state != s {
            self.state = s;
            out.push(Event::EnteredState(s));
        }
    }

    pub fn start(&mut self, out: &mut Vec<Event>) {
        self.last_progress_ms = now_ms();
        self.enter(FsmState::Backup, out);
    }

    pub fn height(&self) -> u64 {
        self.node.height()
    }
    pub fn view(&self) -> u64 {
        self.node.view()
    }
    pub fn id(&self) -> u32 {
        self.node.id()
    }
    /// Присутствие — только как proposer/primary (§13.16.4 MAY).
    pub fn is_proposer(&self) -> bool {
        self.node.is_leader(self.node.view())
    }
    pub fn quorum(&self) -> usize {
        self.node.quorum()
    }
    pub fn finalized_log(&self) -> &[(u64, [u8; 32], Block)] {
        &self.finalized_log
    }
    pub fn finalized_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.node.finalized_hash(height)
    }
    pub fn alive_count(&self) -> usize {
        self.alive.len() + 1
    }
    pub fn current_block(&self) -> Option<&Block> {
        self.current.as_ref()
    }

    /// CONS-005: хранение не более MAX_ROUNDS_TO_KEEP завершённых раундов.
    fn trim_rounds(&mut self) {
        if self.finalized_log.len() > MAX_ROUNDS_TO_KEEP {
            let drop = self.finalized_log.len() - MAX_ROUNDS_TO_KEEP;
            self.finalized_log.drain(..drop);
        }
    }

    /// Proposer создаёт предложение (фаза PREPARE) и рассылает
    /// Proposal + собственный PREPARE-голос.
    pub fn propose(
        &mut self,
        payload: Vec<u8>,
        out: &mut Vec<Event>,
    ) -> Result<Vec<Msg>, ConsensusError> {
        if self.quarantine.contains(&self.node.id()) {
            return Err(ConsensusError::NotLeader);
        }
        let block = self.node.propose(payload)?;
        let sig = self.node.verifier_mut().sign(&proposal_sign_bytes(&block))?;
        self.current = Some(block.clone());
        self.last_progress_ms = now_ms();
        self.enter(FsmState::Prepare, out);
        // proposer учитывает собственный PREPARE-голос и рассылает его
        self.prepares.entry(block.hash()).or_default().insert(self.node.id());
        let mut msgs = vec![Msg::Proposal { block: block.clone(), sig }];
        if let Ok(v) = self.make_vote(&block, PHASE_PREPARE) {
            msgs.push(Msg::PrepareVote(v));
        }
        Ok(msgs)
    }

    /// Обработка входящего сообщения; возвращает исходящие.
    pub fn on_msg(&mut self, m: &Msg, out: &mut Vec<Event>) -> Vec<Msg> {
        let mut tx = Vec::new();
        match m {
            Msg::Alive { node } => {
                if *node == self.node.id() {
                    return tx;
                }
                let was_alive = self.alive.insert(*node);
                if was_alive {
                    tx.extend(self.update_partition_state(out));
                }
            }
            Msg::Proposal { block, sig } => self.on_proposal(block, sig, out, &mut tx),
            Msg::PrepareVote(v) => self.on_phase_vote(v, PHASE_PREPARE, out, &mut tx),
            Msg::CommitVote(v) => self.on_phase_vote(v, PHASE_COMMIT, out, &mut tx),
            Msg::ViewChangeReq { view, node, sig } => {
                self.on_view_change_req(*view, *node, sig, out, &mut tx)
            }
            Msg::NewViewAnnounce { view, node, sig } => {
                self.on_new_view(*view, *node, sig, out, &mut tx)
            }
            Msg::SyncRequest { node, height } => {
                let finalized: Vec<(u64, [u8; 32])> = (0..=*height)
                    .filter_map(|h| self.node.finalized_hash(h).map(|x| (h, x)))
                    .collect();
                // state transfer: полные блоки от запрошенной высоты
                let blocks: Vec<Block> = self
                    .finalized_log
                    .iter()
                    .filter(|(h, _, _)| h >= height)
                    .map(|(_, _, b)| b.clone())
                    .collect();
                tx.push(Msg::SyncResponse {
                    node: self.node.id(),
                    height: self.node.height(),
                    finalized,
                    blocks,
                });
                out.push(Event::RejoinSync(*node));
            }
            Msg::SyncResponse { node, height, finalized, blocks } => {
                let mut consistent = true;
                for (h, hash) in finalized {
                    if let Some(mine) = self.node.finalized_hash(*h) {
                        if &mine != hash {
                            consistent = false;
                            out.push(Event::EvidenceLogged {
                                offender: *node,
                                reason: format!("history divergence at height {h}"),
                            });
                        }
                    }
                }
                if !consistent {
                    return tx;
                }
                // применение недостающих блоков (детерминированно)
                let mut applied_any = false;
                let mut sorted = blocks.clone();
                sorted.sort_by_key(|b| b.height);
                for b in sorted {
                    if b.height != self.node.height() || b.parent_hash != self.node.parent() {
                        continue;
                    }
                    let hash = b.hash();
                    if self.node.import_finalized(b.height, hash).is_err() {
                        out.push(Event::EvidenceLogged {
                            offender: *node,
                            reason: format!("sync block conflicts at height {}", b.height),
                        });
                        continue;
                    }
                    self.finalized_log.push((b.height, hash, b.clone()));
                    self.trim_rounds();
                    out.push(Event::SyncApply(b));
                    applied_any = true;
                }
                if *height <= self.node.height() && !applied_any {
                    if matches!(self.state, FsmState::Sync | FsmState::Recovery) {
                        self.enter(FsmState::Backup, out);
                        self.last_progress_ms = now_ms();
                        out.push(Event::RecoveryDone);
                    }
                } else if matches!(self.state, FsmState::Backup | FsmState::Degraded | FsmState::Isolated) {
                    // догнали — возврат в рабочий цикл
                    if *height <= self.node.height() {
                        self.enter(FsmState::Backup, out);
                        self.last_progress_ms = now_ms();
                        out.push(Event::RecoveryDone);
                    }
                } else if *height > self.node.height() {
                    self.enter(FsmState::Recovery, out);
                    // запросить продолжение
                    tx.push(Msg::SyncRequest { node: self.node.id(), height: self.node.height() });
                } else if applied_any && *height <= self.node.height() {
                    self.enter(FsmState::Backup, out);
                    self.last_progress_ms = now_ms();
                    out.push(Event::RecoveryDone);
                }
            }
        }
        tx
    }

    fn on_proposal(
        &mut self,
        block: &Block,
        sig: &[u8],
        out: &mut Vec<Event>,
        tx: &mut Vec<Msg>,
    ) {
        // 1. подпись proposer'а
        if !self.node.verify_raw_sig(block.proposer, &proposal_sign_bytes(block), sig) {
            out.push(Event::EvidenceLogged {
                offender: block.proposer,
                reason: "invalid proposal signature".into(),
            });
            return;
        }
        // 2. equivocation: тот же (height, view), другой hash, тот же proposer
        let key = (block.height, block.view);
        if let Some((prev_hash, prev_sig, prev_proposer)) = self.proposals_seen.get(&key).cloned() {
            if prev_proposer == block.proposer && prev_hash != block.hash() {
                self.evidence.push(Evidence {
                    offender: block.proposer,
                    height: block.height,
                    view: block.view,
                    hash_a: prev_hash,
                    hash_b: block.hash(),
                    sig_a: prev_sig,
                    sig_b: sig.to_vec(),
                });
                self.quarantine.insert(block.proposer);
                out.push(Event::EvidenceLogged {
                    offender: block.proposer,
                    reason: "equivocation: two proposals in same (height, view)".into(),
                });
                out.push(Event::Quarantined(block.proposer));
                self.enter(FsmState::EvidenceLog, out);
                return;
            }
        }
        self.proposals_seen.insert(key, (block.hash(), sig.to_vec(), block.proposer));

        if block.view != self.node.view() {
            return; // stale/future view — игнор (view-change обработает)
        }
        if block.height != self.node.height() || block.parent_hash != self.node.parent() {
            if block.height > self.node.height() {
                self.enter(FsmState::Recovery, out);
                tx.push(Msg::SyncRequest { node: self.node.id(), height: self.node.height() });
            }
            return;
        }
        if self.quarantine.contains(&block.proposer) {
            return; // предложения quarantined proposer'а не принимаются
        }
        self.current = Some(block.clone());
        self.enter(FsmState::Prepare, out);
        self.last_progress_ms = now_ms();
        if let Ok(v) = self.make_vote(block, PHASE_PREPARE) {
            self.prepares.entry(block.hash()).or_default().insert(self.node.id());
            tx.push(Msg::PrepareVote(v));
        }
        self.check_prepare_quorum(block, out, tx);
    }

    fn make_vote(&mut self, block: &Block, phase: u8) -> Result<Vote, ConsensusError> {
        let hash = block.hash();
        let id = self.node.id();
        let bytes = vote_sign_bytes(&hash, id, block.view, phase);
        let sig = self.node.verifier_mut().sign(&bytes)?;
        Ok(Vote { block_hash: hash, voter: id, view: block.view, signature: sig })
    }

    fn on_phase_vote(&mut self, v: &Vote, phase: u8, out: &mut Vec<Event>, tx: &mut Vec<Msg>) {
        if v.view != self.node.view() || v.voter == self.node.id() {
            return;
        }
        if self.quarantine.contains(&v.voter) {
            return;
        }
        // подпись проверяется ДО обращения к текущему блоку: подделка
        // фиксируется в evidence log независимо от состояния раунда
        let sig_ok = self.node.verify_vote_sig(v, phase);
        if !sig_ok {
            out.push(Event::EvidenceLogged {
                offender: v.voter,
                reason: format!("invalid phase-{phase} vote signature"),
            });
            return;
        }
        let block = match &self.current {
            Some(b) if b.hash() == v.block_hash => b.clone(),
            _ => return, // голос за неизвестный/чужой блок
        };
        if phase == PHASE_PREPARE {
            self.prepares.entry(v.block_hash).or_default().insert(v.voter);
            self.check_prepare_quorum(&block, out, tx);
        } else {
            self.commits.entry(v.block_hash).or_default().insert(v.voter);
            self.check_commit_quorum(&block, out, tx);
        }
    }

    fn check_prepare_quorum(&mut self, block: &Block, out: &mut Vec<Event>, tx: &mut Vec<Msg>) {
        let n = self.prepares.get(&block.hash()).map(|s| s.len()).unwrap_or(0);
        if n >= self.node.quorum() && matches!(self.state, FsmState::Prepare) {
            self.enter(FsmState::Commit, out);
            self.last_progress_ms = now_ms();
            if let Ok(v) = self.make_vote(block, PHASE_COMMIT) {
                self.commits.entry(block.hash()).or_default().insert(self.node.id());
                tx.push(Msg::CommitVote(v));
            }
            self.check_commit_quorum(block, out, tx);
        }
    }

    fn check_commit_quorum(&mut self, block: &Block, out: &mut Vec<Event>, _tx: &mut Vec<Msg>) {
        let n = self.commits.get(&block.hash()).map(|s| s.len()).unwrap_or(0);
        if n < self.node.quorum() {
            return;
        }
        if !matches!(self.state, FsmState::Commit | FsmState::Prepare) {
            return;
        }
        // Мост к референсному узлу C-01: подписи проверены engine'ом,
        // node.votes агрегирует множество голосовавших (дубликаты невозможны).
        let voters: Vec<u32> =
            self.commits.get(&block.hash()).cloned().unwrap_or_default().into_iter().collect();
        for voter in voters {
            let stub = Vote {
                block_hash: block.hash(),
                voter,
                view: block.view,
                signature: Vec::new(),
            };
            let _ = self.node.on_vote(&stub, true);
        }
        match self.node.finalize(block) {
            Ok(()) => {
                self.finalized_log.push((block.height, block.hash(), block.clone()));
                self.trim_rounds();
                self.current = None;
                self.prepares.remove(&block.hash());
                self.commits.remove(&block.hash());
                self.last_progress_ms = now_ms();
                out.push(Event::Finalized { height: block.height, hash: block.hash() });
                self.enter(FsmState::Finalized, out);
                self.enter(FsmState::Backup, out);
            }
            Err(e) => {
                out.push(Event::EvidenceLogged {
                    offender: block.proposer,
                    reason: format!("finalize error: {e:?}"),
                });
            }
        }
    }

    // ---------------- view change ----------------

    fn on_view_change_req(
        &mut self,
        view: u64,
        node: u32,
        sig: &[u8],
        out: &mut Vec<Event>,
        tx: &mut Vec<Msg>,
    ) {
        if view <= self.node.view() || node == self.node.id() {
            return;
        }
        if !self.node.verify_raw_sig(node, &view_change_sign_bytes(view), sig) {
            return;
        }
        if self.quarantine.contains(&node) {
            return;
        }
        if !matches!(self.state, FsmState::ViewChange | FsmState::NewView) {
            self.enter(FsmState::ViewChange, out);
        }
        let reached = {
            let set = self.view_votes.entry(view).or_default();
            set.insert(node);
            // собственный голос учитывается, если мы тоже инициировали смену
            if self.state == FsmState::ViewChange {
                set.insert(self.node.id());
            }
            set.len() >= self.node.quorum()
        };
        if reached {
            let new_proposer = (view % self.node.total() as u64) as u32;
            if new_proposer == self.node.id() {
                if let Ok(sig) = self.node.verifier_mut().sign(&view_change_sign_bytes(view)) {
                    if self.node.view_change(view).is_ok() {
                        self.current = None;
                        self.enter(FsmState::NewView, out);
                        out.push(Event::ViewChanged(view));
                        self.last_progress_ms = now_ms();
                        tx.push(Msg::NewViewAnnounce { view, node: self.node.id(), sig });
                    }
                }
            }
        }
    }

    fn on_new_view(
        &mut self,
        view: u64,
        node: u32,
        sig: &[u8],
        out: &mut Vec<Event>,
        _tx: &mut Vec<Msg>,
    ) {
        if view <= self.node.view() {
            return;
        }
        let expected_proposer = (view % self.node.total() as u64) as u32;
        if node != expected_proposer {
            return;
        }
        if !self.node.verify_raw_sig(node, &view_change_sign_bytes(view), sig) {
            return;
        }
        if self.node.view_change(view).is_ok() {
            self.current = None;
            self.enter(FsmState::NewView, out);
            out.push(Event::ViewChanged(view));
            self.last_progress_ms = now_ms();
            self.enter(FsmState::Backup, out);
        }
    }

    /// Запрос смены view по timeout — рассылается всем.
    pub fn request_view_change(&mut self, out: &mut Vec<Event>) -> Option<Msg> {
        let new_view = self.node.view() + 1;
        let sig = self.node.verifier_mut().sign(&view_change_sign_bytes(new_view)).ok()?;
        self.enter(FsmState::ViewChange, out);
        self.view_votes.entry(new_view).or_default().insert(self.node.id());
        Some(Msg::ViewChangeReq { view: new_view, node: self.node.id(), sig })
    }

    // ---------------- partition / liveness ----------------

    pub fn note_peer_down(&mut self, node: u32, out: &mut Vec<Event>) {
        if self.alive.remove(&node) {
            let _ = self.update_partition_state(out);
        }
    }

    /// Partition-семантика (§13.16.4):
    /// - alive ≥ quorum, но < total → DEGRADED (локальная автономия);
    /// - alive < quorum → ISOLATED (QUORUM_LOST, §13.8 0x000A);
    /// - выход из ISOLATED → SYNC (узел мог пропустить историю) + SyncRequest;
    /// - полное членство из DEGRADED → BACKUP (RecoveryDone).
    fn update_partition_state(&mut self, out: &mut Vec<Event>) -> Vec<Msg> {
        let mut tx = Vec::new();
        let alive = self.alive_count();
        let total = self.node.total() as usize;
        if alive >= self.node.quorum() {
            if self.state == FsmState::Isolated {
                // rejoin: SYNC/RECOVERY (§13.16.4)
                self.enter(FsmState::Sync, out);
                out.push(Event::RejoinSync(self.node.id()));
                tx.push(Msg::SyncRequest { node: self.node.id(), height: self.node.height() });
                self.last_progress_ms = now_ms();
            } else if alive < total {
                if self.state != FsmState::Degraded {
                    self.enter(FsmState::Degraded, out);
                    out.push(Event::PartitionDegraded);
                }
            } else if self.state == FsmState::Degraded {
                self.enter(FsmState::Backup, out);
                out.push(Event::RecoveryDone);
                self.last_progress_ms = now_ms();
            }
        } else if self.state != FsmState::Isolated {
            self.enter(FsmState::Isolated, out);
            out.push(Event::QuorumLostIsolated);
        }
        tx
    }

    /// Периодический тик; `busy` — есть незавершённый раунд или ожидающие
    /// операции (иначе view-change не инициируется — холостой ход запрещён).
    pub fn tick_ext(&mut self, now: u64, out: &mut Vec<Event>, busy: bool) -> Vec<Msg> {
        let mut tx = Vec::new();
        if self.state == FsmState::Isolated && self.alive_count() >= self.node.quorum() {
            self.enter(FsmState::Sync, out);
            tx.push(Msg::SyncRequest { node: self.node.id(), height: self.node.height() });
        } else if self.state == FsmState::Degraded
            && self.alive_count() >= self.node.total() as usize
        {
            self.enter(FsmState::Backup, out);
            out.push(Event::RecoveryDone);
            self.last_progress_ms = now;
        }
        let stalled = now.saturating_sub(self.last_progress_ms) > self.proposer_timeout_ms;
        let working = busy || self.current.is_some();
        // DEGRADED участвует в view change: proposer может остаться за
        // границей партиции при живом кворуме (CONS-008 failover).
        if stalled
            && working
            && matches!(
                self.state,
                FsmState::Backup
                    | FsmState::Prepare
                    | FsmState::Commit
                    | FsmState::Finalized
                    | FsmState::Degraded
            )
        {
            if let Some(m) = self.request_view_change(out) {
                tx.push(m);
            }
        }
        tx
    }

    /// Периодический тик (транспортный watchdog + proposer timeout).
    /// `now` — миллисекунды синхронизированного времени узла.
    pub fn tick(&mut self, now: u64, out: &mut Vec<Event>) -> Vec<Msg> {
        self.tick_ext(now, out, true)
    }
}
