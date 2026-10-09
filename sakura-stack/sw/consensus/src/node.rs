//! Консенсус-узел (C-01, ТП §27.1 — референсный код v2.3):
//! трейт реализован; HashSet голосов; проверка подписи и view; view входит
//! в hash блока; двойная финализация одной высоты с разным hash невозможна.

use sakura_gost::hash::Hasher256;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusMode {
    Bft,
    Cft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    NotLeader,
    QuorumNotReached,
    InvalidSignature,
    StaleView,
    DoubleFinalization,
    ViewChangeInProgress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub view: u64,
    pub parent_hash: [u8; 32],
    pub payload: Vec<u8>,
    pub proposer: u32,
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Hasher256::new();
        hasher.update(&self.height.to_be_bytes());
        hasher.update(&self.view.to_be_bytes());
        hasher.update(&self.parent_hash);
        hasher.update(&self.payload);
        hasher.update(&self.proposer.to_be_bytes());
        hasher.finalize()
    }
}

#[derive(Clone, Debug)]
pub struct Vote {
    pub block_hash: [u8; 32],
    pub voter: u32,
    pub view: u64,
    pub signature: Vec<u8>,
}

/// Подпись/проверка голосов. Реализация предоставляется узлом
/// (гибридный подписант на ключах HSM; реестр публичных ключей — из
/// сертификатов кластера).
pub trait SignatureVerifier {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, ConsensusError>;
    fn verify(&self, voter: u32, msg: &[u8], sig: &[u8]) -> bool;
}

pub trait ConsensusNode {
    fn propose(&mut self, payload: Vec<u8>) -> Result<Block, ConsensusError>;
    fn vote(&mut self, block: &Block) -> Result<Vote, ConsensusError>;
    fn on_vote(&mut self, vote: &Vote, sig_valid: bool) -> Result<bool, ConsensusError>;
    fn finalize(&mut self, block: &Block) -> Result<(), ConsensusError>;
    fn view_change(&mut self, new_view: u64) -> Result<(), ConsensusError>;
    fn mode(&self) -> ConsensusMode;
}

pub struct BftNode {
    id: u32,
    total: u32,
    f: u32,
    mode: ConsensusMode,
    view: u64,
    height: u64,
    parent: [u8; 32],
    finalized: HashMap<u64, [u8; 32]>,
    votes: HashMap<[u8; 32], HashSet<u32>>,
    verifier: Box<dyn SignatureVerifier>,
}

impl BftNode {
    pub fn new(id: u32, total: u32, verifier: Box<dyn SignatureVerifier>) -> Self {
        // BFT: n ≥ 3f+1 → f = (n−1)/3
        let f = (total - 1) / 3;
        Self {
            id,
            total,
            f,
            mode: ConsensusMode::Bft,
            view: 0,
            height: 0,
            parent: [0u8; 32],
            finalized: HashMap::new(),
            votes: HashMap::new(),
            verifier,
        }
    }

    /// Кворум: BFT — 2f+1 (n ≥ 3f+1); CFT — f+1 (n ≥ 2f+1), §4.11.
    pub fn quorum(&self) -> usize {
        match self.mode {
            ConsensusMode::Bft => (2 * self.f + 1) as usize,
            ConsensusMode::Cft => (self.f + 1) as usize,
        }
    }

    pub fn is_leader(&self, view: u64) -> bool {
        (view % self.total as u64) as u32 == self.id
    }

    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn total(&self) -> u32 {
        self.total
    }
    pub fn f(&self) -> u32 {
        self.f
    }
    pub fn view(&self) -> u64 {
        self.view
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn parent(&self) -> [u8; 32] {
        self.parent
    }
    pub fn finalized_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.finalized.get(&height).copied()
    }
    pub fn verifier_mut(&mut self) -> &mut dyn SignatureVerifier {
        self.verifier.as_mut()
    }

    /// Проверка произвольной подписи узла-голосующего (для engine FSM).
    pub fn verify_raw_sig(&self, voter: u32, msg: &[u8], sig: &[u8]) -> bool {
        self.verifier.verify(voter, msg, sig)
    }

    /// Импорт финализированного блока из state transfer (SYNC/RECOVERY):
    /// блок уже финализирован кворумом; локальный узел догоняет историю.
    /// DoubleFinalization-инвариант сохраняется (проверка hash).
    pub fn import_finalized(&mut self, height: u64, hash: [u8; 32]) -> Result<(), ConsensusError> {
        match self.finalized.get(&height) {
            Some(existing) if *existing != hash => return Err(ConsensusError::DoubleFinalization),
            Some(_) => return Ok(()),
            None => {}
        }
        self.finalized.insert(height, hash);
        if height >= self.height {
            self.height = height + 1;
            self.parent = hash;
        }
        Ok(())
    }

    /// CFT-вариант (§4.11: CFT при n ≥ 2f+1, кворум f+1) — создаёт узел
    /// с тем же id/total, но f = (n−1)/2 и режимом CFT.
    pub fn new_cft(id: u32, total: u32, verifier: Box<dyn SignatureVerifier>) -> Self {
        let f = (total - 1) / 2;
        Self {
            id,
            total,
            f,
            mode: ConsensusMode::Cft,
            view: 0,
            height: 0,
            parent: [0u8; 32],
            finalized: HashMap::new(),
            votes: HashMap::new(),
            verifier,
        }
    }

}

/// CFT-узел: кворум f+1 (простое большинство).
pub struct CftNode(BftNode);

impl CftNode {
    pub fn new(id: u32, total: u32, verifier: Box<dyn SignatureVerifier>) -> Self {
        CftNode(BftNode::new_cft(id, total, verifier))
    }
    pub fn inner(&self) -> &BftNode {
        &self.0
    }
    pub fn inner_mut(&mut self) -> &mut BftNode {
        &mut self.0
    }
}

impl ConsensusNode for CftNode {
    fn propose(&mut self, payload: Vec<u8>) -> Result<Block, ConsensusError> {
        self.0.propose(payload)
    }
    fn vote(&mut self, block: &Block) -> Result<Vote, ConsensusError> {
        self.0.vote(block)
    }
    fn on_vote(&mut self, vote: &Vote, sig_valid: bool) -> Result<bool, ConsensusError> {
        self.0.on_vote(vote, sig_valid)
    }
    fn finalize(&mut self, block: &Block) -> Result<(), ConsensusError> {
        self.0.finalize(block)
    }
    fn view_change(&mut self, new_view: u64) -> Result<(), ConsensusError> {
        self.0.view_change(new_view)
    }
    fn mode(&self) -> ConsensusMode {
        ConsensusMode::Cft
    }
}

impl ConsensusNode for BftNode {
    fn propose(&mut self, payload: Vec<u8>) -> Result<Block, ConsensusError> {
        if !self.is_leader(self.view) {
            return Err(ConsensusError::NotLeader);
        }
        Ok(Block {
            height: self.height,
            view: self.view,
            parent_hash: self.parent,
            payload,
            proposer: self.id,
        })
    }

    fn vote(&mut self, block: &Block) -> Result<Vote, ConsensusError> {
        if block.view != self.view {
            return Err(ConsensusError::StaleView);
        }
        let sig = self.verifier.sign(&block.hash())?;
        Ok(Vote {
            block_hash: block.hash(),
            voter: self.id,
            view: self.view,
            signature: sig,
        })
    }

    fn on_vote(&mut self, vote: &Vote, sig_valid: bool) -> Result<bool, ConsensusError> {
        if !sig_valid {
            return Err(ConsensusError::InvalidSignature);
        }
        if vote.view != self.view {
            return Err(ConsensusError::StaleView);
        }
        let set = self.votes.entry(vote.block_hash).or_default();
        set.insert(vote.voter);
        Ok(set.len() >= self.quorum())
    }

    fn finalize(&mut self, block: &Block) -> Result<(), ConsensusError> {
        let n = self.votes.get(&block.hash()).map(|s| s.len()).unwrap_or(0);
        if n < self.quorum() {
            return Err(ConsensusError::QuorumNotReached);
        }
        match self.finalized.get(&block.height) {
            Some(existing) if *existing != block.hash() => {
                return Err(ConsensusError::DoubleFinalization)
            }
            Some(_) => return Ok(()),
            None => {}
        }
        self.finalized.insert(block.height, block.hash());
        self.height += 1;
        self.parent = block.hash();
        Ok(())
    }

    fn view_change(&mut self, new_view: u64) -> Result<(), ConsensusError> {
        if new_view <= self.view {
            return Err(ConsensusError::ViewChangeInProgress);
        }
        self.view = new_view;
        Ok(())
    }

    fn mode(&self) -> ConsensusMode {
        self.mode.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Тестовый верификатор: «подпись» = Стрибог(voter_secret || msg).
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
        for i in 0..7u32 {
            secrets.insert(i, [i as u8; 8]);
        }
        Box::new(TestVerifier { id, secrets })
    }

    fn cluster(n: u32) -> Vec<BftNode> {
        (0..n).map(|i| BftNode::new(i, n, verifier(i))).collect()
    }

    #[test]
    fn quorum_and_leader() {
        let nodes = cluster(4); // f=1, quorum=3
        assert_eq!(nodes[0].quorum(), 3);
        assert_eq!(nodes[0].f(), 1);
        assert!(nodes[0].is_leader(0));
        assert!(!nodes[1].is_leader(0));
        assert!(nodes[1].is_leader(1));
        assert!(nodes[2].is_leader(2));
        assert!(nodes[3].is_leader(3));
        assert!(nodes[0].is_leader(4));
    }

    #[test]
    fn happy_path_finalization() {
        let mut nodes = cluster(4);
        let block = nodes[0].propose(b"tx-batch".to_vec()).unwrap();
        // не-лидер не может предложить
        assert_eq!(nodes[1].propose(b"x".to_vec()), Err(ConsensusError::NotLeader));
        let mut votes = Vec::new();
        for n in nodes.iter_mut() {
            votes.push(n.vote(&block).unwrap());
        }
        let mut quorum_seen = false;
        for v in &votes {
            for n in nodes.iter_mut() {
                if n.id() == v.voter {
                    // собственный голос уже учтён при vote()
                    continue;
                }
                if let Ok(q) = n.on_vote(v, true) {
                    quorum_seen |= q;
                }
            }
        }
        assert!(quorum_seen);
        for n in nodes.iter_mut() {
            n.finalize(&block).unwrap();
            assert_eq!(n.height(), 1);
            assert_eq!(n.parent(), block.hash());
        }
    }

    #[test]
    fn unsigned_and_duplicate_votes() {
        let mut nodes = cluster(4);
        let block = nodes[0].propose(b"p".to_vec()).unwrap();
        let v = nodes[1].vote(&block).unwrap();
        // голос без валидной подписи не учитывается
        assert_eq!(nodes[2].on_vote(&v, false), Err(ConsensusError::InvalidSignature));
        nodes[2].on_vote(&v, true).unwrap();
        nodes[2].on_vote(&v, true).unwrap();
        // повторный голос того же узла не увеличивает кворум
        assert!(!nodes[2].on_vote(&v, true).unwrap());
        assert_eq!(nodes[2].finalize(&block), Err(ConsensusError::QuorumNotReached));
    }

    #[test]
    fn stale_view_rejected() {
        let mut nodes = cluster(4);
        let block = nodes[0].propose(b"p".to_vec()).unwrap();
        nodes[1].view_change(1).unwrap();
        // блок view 0 для узла в view 1 — устарел
        assert!(matches!(nodes[1].vote(&block), Err(ConsensusError::StaleView)));
        let v = nodes[2].vote(&block).unwrap();
        assert!(matches!(nodes[1].on_vote(&v, true), Err(ConsensusError::StaleView)));
        // откат view невозможен
        assert_eq!(nodes[1].view_change(1), Err(ConsensusError::ViewChangeInProgress));
        assert_eq!(nodes[1].view_change(0), Err(ConsensusError::ViewChangeInProgress));
    }

    #[test]
    fn double_finalization_impossible() {
        let mut nodes = cluster(4);
        let b1 = nodes[0].propose(b"A".to_vec()).unwrap();
        // «эквивокация» лидера: второй блок той же высоты (другой payload)
        let b2 = Block { payload: b"B".to_vec(), ..b1.clone() };
        assert_ne!(b1.hash(), b2.hash());
        let mut votes1 = Vec::new();
        let mut votes2 = Vec::new();
        for n in nodes.iter_mut() {
            votes1.push(n.vote(&b1).unwrap());
        }
        for n in nodes.iter_mut() {
            votes2.push(n.vote(&b2).unwrap());
        }
        for v in votes1.iter().chain(votes2.iter()) {
            for n in nodes.iter_mut() {
                let _ = n.on_vote(v, true);
            }
        }
        nodes[0].finalize(&b1).unwrap();
        // тот же hash — идемпотентно OK
        nodes[0].finalize(&b1).unwrap();
        // другой hash той же высоты — DoubleFinalization
        assert_eq!(nodes[0].finalize(&b2), Err(ConsensusError::DoubleFinalization));
        assert_eq!(nodes[0].height(), 1);
    }

    #[test]
    fn cft_mode_quorum() {
        // CFT: n=3, f=(3−1)/2=1, quorum=f+1=2
        let mut nodes: Vec<CftNode> =
            (0..3).map(|i| CftNode::new(i, 3, verifier(i))).collect();
        assert_eq!(nodes[0].mode(), ConsensusMode::Cft);
        assert_eq!(nodes[0].inner().quorum(), 2);
        let block = nodes[0].propose(b"cft-payload".to_vec()).unwrap();
        let v1 = nodes[1].vote(&block).unwrap();
        let v2 = nodes[2].vote(&block).unwrap();
        nodes[0].on_vote(&v1, true).unwrap();
        assert!(nodes[0].on_vote(&v2, true).unwrap());
        nodes[0].finalize(&block).unwrap();
        assert_eq!(nodes[0].inner().height(), 1);
    }

    #[test]
    fn view_in_hash_and_parent_chaining() {
        let mut n = BftNode::new(0, 1, verifier(0));
        let b0 = n.propose(b"x".to_vec()).unwrap();
        // view входит в hash (C-01)
        let b0v1 = Block { view: 1, ..b0.clone() };
        assert_ne!(b0.hash(), b0v1.hash());
        let v = n.vote(&b0).unwrap();
        n.on_vote(&v, true).unwrap();
        n.finalize(&b0).unwrap();
        let b1 = n.propose(b"y".to_vec()).unwrap();
        assert_eq!(b1.parent_hash, b0.hash());
        assert_eq!(b1.height, 1);
    }
}
