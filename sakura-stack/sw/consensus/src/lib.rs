//! sakura-consensus — L6 Consensus & Distribution (§5.8):
//! - [`node`] — референсный BFT/CFT-узел (C-01, ТП §27.1);
//! - [`engine`] — Consensus FSM в BFT-терминах (BC-23): PREPARE/COMMIT/
//!   FINALIZED/VIEW_CHANGE/NEW_VIEW/DEGRADED/ISOLATED/SYNC/RECOVERY/
//!   QUARANTINE/EVIDENCE_LOG, equivocation-детекция.
#![forbid(unsafe_code)]

pub mod engine;
pub mod node;

pub use engine::{Engine, Event, Evidence, FsmState, Msg, PHASE_COMMIT, PHASE_PREPARE};
pub use node::{
    BftNode, Block, CftNode, ConsensusError, ConsensusMode, ConsensusNode, SignatureVerifier, Vote,
};

/// Проверка подписи голоса engine-верификатором (фаза входит в подписываемые
/// байты — защита от кросс-фазового replay голоса).
impl BftNode {
    pub fn verify_vote_sig(&self, v: &Vote, phase: u8) -> bool {
        let bytes = engine::vote_sign_bytes(&v.block_hash, v.voter, v.view, phase);
        self.verify_raw_sig(v.voter, &bytes, &v.signature)
    }
}
