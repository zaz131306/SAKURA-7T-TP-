//! sakura-policy — L4 Policy & Ethics (§5.6, BC-33):
//! - RBAC/ABAC управляющих команд (API-1 SubmitCommand);
//! - Ethics Governor, 3 уровня (ETH-002): hard constraints (не
//!   переопределяются, ETH-003) → policy constraints → anomaly detection;
//! - запрет автономных летальных действий (§24.6, ETH-005/006) —
//!   программно-аппаратный, baseline;
//! - lifecycle phases (LIFE-001) ↔ operating modes (BC-22, таблица 1.6.2);
//! - two-person rule (§13.19.2 EmergencyStop, §25.2 high-risk);
//! - authorized decommission 3-из-5 + подписи (LIFE-005);
//! - приоритеты режимов (§25.1): безопасность людей > ключи > управляющие
//!   воздействия > доступность > целостность > аналитика > обучение > комфорт.
#![forbid(unsafe_code)]

use sakura_common::cbor::Cbor;
use sakura_gost::hash::streebog256;
use sakura_hybrid::{hybrid_verify, HybridPublicKey};
use std::collections::{BTreeMap, BTreeSet};

// ---------------- Команда (DM-1 Plan.commands) ----------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub plan_id: [u8; 16],
    pub command_id: [u8; 16],
    pub seq: u64,
    pub cmd_type: String,
    pub payload: Vec<u8>,
    pub target: String,
}

impl Command {
    /// Каноническое представление для подписи оператора (DM-1:
    /// детерминированный CBOR).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Cbor::map(vec![
            (Cbor::text("plan_id"), Cbor::bytes(self.plan_id.to_vec())),
            (Cbor::text("command_id"), Cbor::bytes(self.command_id.to_vec())),
            (Cbor::text("seq"), Cbor::UInt(self.seq)),
            (Cbor::text("cmd_type"), Cbor::text(self.cmd_type.clone())),
            (Cbor::text("payload"), Cbor::bytes(self.payload.clone())),
            (Cbor::text("target"), Cbor::text(self.target.clone())),
        ])
        .to_vec()
    }
}

// ---------------- Роли (RBAC) ----------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Admin = 0,
    SafetyOfficer = 1,
    Operator = 2,
    Auditor = 3,
    Service = 4,
}

impl Role {
    pub fn from_str_name(s: &str) -> Option<Role> {
        Some(match s {
            "ADMIN" => Role::Admin,
            "SAFETY_OFFICER" => Role::SafetyOfficer,
            "OPERATOR" => Role::Operator,
            "AUDITOR" => Role::Auditor,
            "SERVICE" => Role::Service,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "ADMIN",
            Role::SafetyOfficer => "SAFETY_OFFICER",
            Role::Operator => "OPERATOR",
            Role::Auditor => "AUDITOR",
            Role::Service => "SERVICE",
        }
    }
}

// ---------------- Lifecycle (LIFE-001, BC-22) ----------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LifecyclePhase {
    Provisioning,
    Operational,
    Degraded,
    Isolated,
    Recovery,
    Decommission,
}

impl LifecyclePhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            LifecyclePhase::Provisioning => "PROVISIONING",
            LifecyclePhase::Operational => "OPERATIONAL",
            LifecyclePhase::Degraded => "DEGRADED",
            LifecyclePhase::Isolated => "ISOLATED",
            LifecyclePhase::Recovery => "RECOVERY",
            LifecyclePhase::Decommission => "DECOMMISSION",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "PROVISIONING" => LifecyclePhase::Provisioning,
            "OPERATIONAL" => LifecyclePhase::Operational,
            "DEGRADED" => LifecyclePhase::Degraded,
            "ISOLATED" => LifecyclePhase::Isolated,
            "RECOVERY" => LifecyclePhase::Recovery,
            "DECOMMISSION" => LifecyclePhase::Decommission,
            _ => return None,
        })
    }
}

/// Operating modes (BC-22, таблица 1.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperatingMode {
    Normal,
    BftMode,
    CftMode,
    DegradedNet,
    DegradedCompute,
    Isolated,
    AirGap,
    Maintenance,
    Training,
    SecureLockdown,
    EmergencyStop,
    Recovery,
    Locked,
    Sanitizing,
}

impl OperatingMode {
    pub fn as_str(&self) -> &'static str {
        use OperatingMode::*;
        match self {
            Normal => "NORMAL",
            BftMode => "BFT_MODE",
            CftMode => "CFT_MODE",
            DegradedNet => "DEGRADED_NET",
            DegradedCompute => "DEGRADED_COMPUTE",
            Isolated => "ISOLATED",
            AirGap => "AIR_GAP",
            Maintenance => "MAINTENANCE",
            Training => "TRAINING",
            SecureLockdown => "SECURE_LOCKDOWN",
            EmergencyStop => "EMERGENCY_STOP",
            Recovery => "RECOVERY",
            Locked => "LOCKED",
            Sanitizing => "SANITIZING",
        }
    }

    /// LIFE-001a (BC-22): маппинг режимов на фазы жизненного цикла.
    pub fn lifecycle_phase(&self) -> LifecyclePhase {
        use OperatingMode::*;
        match self {
            Normal | BftMode | CftMode => LifecyclePhase::Operational,
            DegradedNet | DegradedCompute => LifecyclePhase::Degraded,
            Isolated | AirGap | SecureLockdown | EmergencyStop => LifecyclePhase::Isolated,
            Maintenance | Training | Recovery => LifecyclePhase::Recovery,
            Locked | Sanitizing => LifecyclePhase::Decommission,
        }
    }
}

// ---------------- Политический документ ----------------

/// Hard constraints (ETH-003): категории команд, запрещённые безусловно
/// (§24.6: baseline поставляется с запретом autonomous engagement).
pub const HARD_FORBIDDEN_PREFIXES: &[&str] =
    &["LETHAL_", "WEAPON_", "AUTONOMOUS_ENGAGE", "TARGET_SELECT_"];

#[derive(Clone, Debug)]
pub struct PolicyDoc {
    /// RBAC: роль → разрешённые префиксы cmd_type ("*" = все не запрещённые).
    pub rbac: BTreeMap<Role, BTreeSet<String>>,
    /// Команды, требующие two-person rule (§25.2 high-risk).
    pub two_person_types: BTreeSet<String>,
    /// Allowlist хэшей моделей T8 (BC-35; Стрибог-512).
    pub model_allowlist: Vec<[u8; 64]>,
    /// Максимальный уровень автономности (ETH-004: L3).
    pub autonomy_max: u8,
    /// Anomaly-порог: команд на принципала в минуту (уровень 3, ETH-002).
    pub anomaly_cmds_per_minute: u32,
}

impl Default for PolicyDoc {
    fn default() -> Self {
        let mut rbac = BTreeMap::new();
        rbac.insert(Role::Admin, set_of(&["*"]));
        rbac.insert(Role::Operator, set_of(&["KV_", "PLAN_", "SENSOR_", "STATUS", "HEARTBEAT"]));
        rbac.insert(Role::SafetyOfficer, set_of(&["EMERGENCY_", "SAFETY_", "RECOVERY_", "STATUS"]));
        rbac.insert(Role::Auditor, set_of(&["AUDIT_", "STATUS"]));
        rbac.insert(Role::Service, set_of(&["HEARTBEAT", "STATUS"]));
        PolicyDoc {
            rbac,
            two_person_types: set_of(&["EMERGENCY_STOP", "DECOMMISSION_AUTHORIZE", "KEY_CEREMONY", "ZEROIZE", "OTA_APPLY"]),
            model_allowlist: Vec::new(),
            autonomy_max: 3,
            anomaly_cmds_per_minute: 120,
        }
    }
}

fn set_of(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl PolicyDoc {
    /// policy_hash = Стрибог-256 от canonical CBOR (§13.17 policy binding).
    pub fn policy_hash(&self) -> [u8; 32] {
        streebog256(&self.to_cbor().to_vec())
    }

    pub fn to_cbor(&self) -> Cbor {
        let rbac: Vec<Cbor> = self
            .rbac
            .iter()
            .map(|(r, types)| {
                Cbor::map(vec![
                    (Cbor::text("role"), Cbor::text(r.as_str())),
                    (
                        Cbor::text("types"),
                        Cbor::array(types.iter().map(|t| Cbor::text(t.clone())).collect()),
                    ),
                ])
            })
            .collect();
        Cbor::map(vec![
            (Cbor::text("version"), Cbor::text("2.3")),
            (Cbor::text("rbac"), Cbor::array(rbac)),
            (
                Cbor::text("two_person_types"),
                Cbor::array(self.two_person_types.iter().map(|t| Cbor::text(t.clone())).collect()),
            ),
            (
                Cbor::text("model_allowlist"),
                Cbor::array(self.model_allowlist.iter().map(|m| Cbor::bytes(m.to_vec())).collect()),
            ),
            (Cbor::text("autonomy_max"), Cbor::UInt(self.autonomy_max as u64)),
            (Cbor::text("anomaly_cmds_per_minute"), Cbor::UInt(self.anomaly_cmds_per_minute as u64)),
            (
                Cbor::text("hard_forbidden"),
                Cbor::array(HARD_FORBIDDEN_PREFIXES.iter().map(|p| Cbor::text(*p)).collect()),
            ),
        ])
    }
}

// ---------------- Решения ----------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    /// Разрешено при наличии второго подтверждения (two-person rule).
    AllowWithSecondSignature,
    Deny(sakura_common::ErrorCode, String),
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow | PolicyDecision::AllowWithSecondSignature)
    }
}

// ---------------- Движок ----------------

pub struct PolicyEngine {
    pub doc: PolicyDoc,
    pub mode: OperatingMode,
    /// Скользящие окна anomaly detection (принципал → timestamps, мин).
    anomaly: BTreeMap<[u8; 16], Vec<u64>>,
}

impl PolicyEngine {
    pub fn new(doc: PolicyDoc, mode: OperatingMode) -> Self {
        PolicyEngine { doc, mode, anomaly: BTreeMap::new() }
    }

    pub fn policy_hash(&self) -> [u8; 32] {
        self.doc.policy_hash()
    }

    pub fn phase(&self) -> LifecyclePhase {
        self.mode.lifecycle_phase()
    }

    /// Смена операционного режима (валидация перехода — LIFE-001a).
    pub fn set_mode(&mut self, mode: OperatingMode) -> Result<(), &'static str> {
        // из SANITIZING/LOCKED возврат только через REPROVISION (ceremony)
        if matches!(self.mode, OperatingMode::Sanitizing)
            && !matches!(mode, OperatingMode::Sanitizing)
        {
            return Err("SANITIZING is terminal (LIFE-002)");
        }
        // EMERGENCY_STOP снимается только переходом в RECOVERY (§25.1)
        if self.mode == OperatingMode::EmergencyStop
            && !matches!(mode, OperatingMode::EmergencyStop | OperatingMode::Recovery)
        {
            return Err("EMERGENCY_STOP exits only via RECOVERY");
        }
        self.mode = mode;
        Ok(())
    }

    /// Ethics Governor — 3 уровня (ETH-002).
    /// Уровень 1: hard constraints (ETH-003/005/006) — не переопределяются.
    /// Уровень 2: RBAC/policy + two-person.
    /// Уровень 3: anomaly detection (частота команд принципала).
    pub fn authorize(
        &mut self,
        role: Role,
        actor_id: &[u8; 16],
        cmd: &Command,
        now_s: u64,
    ) -> PolicyDecision {
        use sakura_common::ErrorCode::*;
        // --- уровень 1: hard constraints (§24.6) ---
        for p in HARD_FORBIDDEN_PREFIXES {
            if cmd.cmd_type.starts_with(p) {
                return PolicyDecision::Deny(
                    EthicsRejected,
                    format!("hard constraint: forbidden category {p} (ETH-005/006, §24.6)"),
                );
            }
        }
        // автономность выше L3 запрещена (ETH-004) — маркировка в payload-заголовке
        if cmd.cmd_type.starts_with("AUTONOMY_L") {
            if let Some(l) = cmd.cmd_type.chars().last().and_then(|c| c.to_digit(10)) {
                if l > self.doc.autonomy_max as u32 {
                    return PolicyDecision::Deny(
                        EthicsRejected,
                        format!("autonomy level L{l} > max L{} (ETH-004)", self.doc.autonomy_max),
                    );
                }
            }
        }
        // --- режимные ограничения (§25.1 приоритеты) ---
        match self.mode {
            OperatingMode::EmergencyStop => {
                if !matches!(cmd.cmd_type.as_str(), "STATUS" | "RECOVERY_ENTER" | "AUDIT_EXPORT") {
                    return PolicyDecision::Deny(
                        PolicyViolation,
                        "EMERGENCY_STOP active: only STATUS/RECOVERY_ENTER/AUDIT_EXPORT".into(),
                    );
                }
            }
            OperatingMode::SecureLockdown => {
                if !cmd.cmd_type.starts_with("AUDIT_") && cmd.cmd_type != "STATUS" {
                    return PolicyDecision::Deny(
                        PolicyViolation,
                        "SECURE_LOCKDOWN: control commands blocked".into(),
                    );
                }
            }
            OperatingMode::Sanitizing | OperatingMode::Locked => {
                return PolicyDecision::Deny(
                    PolicyViolation,
                    format!("mode {} rejects all commands", self.mode.as_str()),
                );
            }
            _ => {}
        }
        // --- уровень 2: RBAC ---
        let allowed = match self.doc.rbac.get(&role) {
            Some(types) => types.iter().any(|t| t == "*" || cmd.cmd_type.starts_with(t.as_str())),
            None => false,
        };
        if !allowed {
            return PolicyDecision::Deny(
                PolicyViolation,
                format!("RBAC: role {} not permitted for {}", role.as_str(), cmd.cmd_type),
            );
        }
        // --- уровень 3: anomaly detection (ETH-002) ---
        let window = self.anomaly.entry(*actor_id).or_default();
        window.retain(|&t| now_s.saturating_sub(t) < 60);
        window.push(now_s);
        if window.len() as u32 > self.doc.anomaly_cmds_per_minute {
            return PolicyDecision::Deny(
                RateLimit,
                format!("anomaly: >{} cmds/min for principal (ETH-002 L3)", self.doc.anomaly_cmds_per_minute),
            );
        }
        // --- two-person rule (§13.19.2, §25.2) ---
        if self.doc.two_person_types.contains(&cmd.cmd_type)
            || cmd.cmd_type.starts_with("EMERGENCY_")
        {
            return PolicyDecision::AllowWithSecondSignature;
        }
        PolicyDecision::Allow
    }

    /// Проверка двух подписей двух РАЗНЫХХ операторов (two-person rule):
    /// обе подписи валидны, субъекты различны.
    pub fn verify_two_person(
        cmd: &Command,
        pk1: &HybridPublicKey,
        sig1: &[u8],
        pk2: &HybridPublicKey,
        sig2: &[u8],
    ) -> Result<(), &'static str> {
        if pk1.to_bytes() == pk2.to_bytes() {
            return Err("two-person rule requires DISTINCT operators");
        }
        let data = cmd.canonical_bytes();
        if !hybrid_verify(pk1, &data, sig1) {
            return Err("first operator signature invalid");
        }
        if !hybrid_verify(pk2, &data, sig2) {
            return Err("second operator signature invalid");
        }
        Ok(())
    }

    /// Authorized decommission: 3 из 5 custodians + подписи (LIFE-005).
    pub fn verify_decommission_quorum(
        ceremony_id: &[u8],
        custodians: &[(HybridPublicKey, Vec<u8>)],
    ) -> Result<usize, &'static str> {
        const THRESHOLD: usize = 3;
        if custodians.len() > 5 {
            return Err("custodian set must be ≤5");
        }
        let mut distinct: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        let mut valid = 0usize;
        for (pk, sig) in custodians {
            if !hybrid_verify(pk, ceremony_id, sig) {
                continue;
            }
            let key = pk.to_bytes();
            if distinct.insert(key, ()).is_some() {
                continue; // дубликаты custodian не учитываются
            }
            valid += 1;
        }
        if valid >= THRESHOLD {
            Ok(valid)
        } else {
            Err("3-of-5 quorum not reached")
        }
    }

    /// Model attestation gate (BC-35, §22.24): хэш модели (Стрибог-512)
    /// обязан присутствовать в allowlist.
    pub fn model_allowed(&self, model_hash: &[u8; 64]) -> bool {
        self.doc.model_allowlist.iter().any(|m| m == model_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    fn cmd(t: &str) -> Command {
        Command {
            plan_id: [1u8; 16],
            command_id: [2u8; 16],
            seq: 1,
            cmd_type: t.to_owned(),
            payload: b"p".to_vec(),
            target: "node-1".to_owned(),
        }
    }

    #[test]
    fn hard_constraints_never_overridable() {
        let mut eng = PolicyEngine::new(PolicyDoc::default(), OperatingMode::Normal);
        // даже ADMIN с "*" не может выполнить летальную команду (§24.6)
        let d = eng.authorize(Role::Admin, &[3u8; 16], &cmd("LETHAL_STRIKE"), 100);
        assert!(matches!(d, PolicyDecision::Deny(sakura_common::ErrorCode::EthicsRejected, _)));
        let d2 = eng.authorize(Role::Admin, &[3u8; 16], &cmd("WEAPON_ARM"), 100);
        assert!(matches!(d2, PolicyDecision::Deny(sakura_common::ErrorCode::EthicsRejected, _)));
        let d3 = eng.authorize(Role::Admin, &[3u8; 16], &cmd("AUTONOMY_L4"), 100);
        assert!(matches!(d3, PolicyDecision::Deny(sakura_common::ErrorCode::EthicsRejected, _)));
        // L3 — разрешён (ETH-004 max L3)
        assert!(eng.authorize(Role::Admin, &[3u8; 16], &cmd("AUTONOMY_L3"), 100).is_allowed());
    }

    #[test]
    fn rbac_matrix() {
        let mut eng = PolicyEngine::new(PolicyDoc::default(), OperatingMode::Normal);
        assert_eq!(eng.authorize(Role::Operator, &[1u8; 16], &cmd("KV_PUT"), 100), PolicyDecision::Allow);
        assert!(matches!(
            eng.authorize(Role::Operator, &[1u8; 16], &cmd("AUDIT_EXPORT"), 100),
            PolicyDecision::Deny(sakura_common::ErrorCode::PolicyViolation, _)
        ));
        assert_eq!(eng.authorize(Role::Auditor, &[2u8; 16], &cmd("AUDIT_EXPORT"), 100), PolicyDecision::Allow);
        // two-person типы
        assert_eq!(
            eng.authorize(Role::SafetyOfficer, &[3u8; 16], &cmd("EMERGENCY_STOP"), 100),
            PolicyDecision::AllowWithSecondSignature
        );
        assert_eq!(
            eng.authorize(Role::Admin, &[3u8; 16], &cmd("OTA_APPLY"), 100),
            PolicyDecision::AllowWithSecondSignature
        );
    }

    #[test]
    fn mode_restrictions_priority() {
        let mut eng = PolicyEngine::new(PolicyDoc::default(), OperatingMode::EmergencyStop);
        // §25.1: приоритет безопасности — управляющие команды блокированы
        assert!(matches!(
            eng.authorize(Role::Admin, &[1u8; 16], &cmd("KV_PUT"), 100),
            PolicyDecision::Deny(sakura_common::ErrorCode::PolicyViolation, _)
        ));
        assert_eq!(eng.authorize(Role::Auditor, &[2u8; 16], &cmd("STATUS"), 100), PolicyDecision::Allow);
        // снятие только через RECOVERY
        assert!(eng.set_mode(OperatingMode::Normal).is_err());
        eng.set_mode(OperatingMode::Recovery).unwrap();
        eng.set_mode(OperatingMode::Normal).unwrap();
        assert_eq!(eng.authorize(Role::Operator, &[1u8; 16], &cmd("KV_PUT"), 200), PolicyDecision::Allow);
    }

    #[test]
    fn anomaly_detection_level3() {
        let mut doc = PolicyDoc::default();
        doc.anomaly_cmds_per_minute = 3;
        let mut eng = PolicyEngine::new(doc, OperatingMode::Normal);
        let actor = [7u8; 16];
        assert!(eng.authorize(Role::Operator, &actor, &cmd("KV_PUT"), 1000).is_allowed());
        assert!(eng.authorize(Role::Operator, &actor, &cmd("KV_PUT"), 1010).is_allowed());
        assert!(eng.authorize(Role::Operator, &actor, &cmd("KV_PUT"), 1020).is_allowed());
        assert_eq!(
            eng.authorize(Role::Operator, &actor, &cmd("KV_PUT"), 1030),
            PolicyDecision::Deny(sakura_common::ErrorCode::RateLimit, "anomaly: >3 cmds/min for principal (ETH-002 L3)".into())
        );
        // через минуту окно очищается
        assert!(eng.authorize(Role::Operator, &actor, &cmd("KV_PUT"), 1075).is_allowed());
    }

    #[test]
    fn lifecycle_mode_mapping_bc22() {
        assert_eq!(OperatingMode::Normal.lifecycle_phase(), LifecyclePhase::Operational);
        assert_eq!(OperatingMode::BftMode.lifecycle_phase(), LifecyclePhase::Operational);
        assert_eq!(OperatingMode::CftMode.lifecycle_phase(), LifecyclePhase::Operational);
        assert_eq!(OperatingMode::DegradedNet.lifecycle_phase(), LifecyclePhase::Degraded);
        assert_eq!(OperatingMode::DegradedCompute.lifecycle_phase(), LifecyclePhase::Degraded);
        assert_eq!(OperatingMode::Isolated.lifecycle_phase(), LifecyclePhase::Isolated);
        assert_eq!(OperatingMode::AirGap.lifecycle_phase(), LifecyclePhase::Isolated);
        assert_eq!(OperatingMode::SecureLockdown.lifecycle_phase(), LifecyclePhase::Isolated);
        assert_eq!(OperatingMode::EmergencyStop.lifecycle_phase(), LifecyclePhase::Isolated);
        assert_eq!(OperatingMode::Maintenance.lifecycle_phase(), LifecyclePhase::Recovery);
        assert_eq!(OperatingMode::Training.lifecycle_phase(), LifecyclePhase::Recovery);
        assert_eq!(OperatingMode::Recovery.lifecycle_phase(), LifecyclePhase::Recovery);
        assert_eq!(OperatingMode::Locked.lifecycle_phase(), LifecyclePhase::Decommission);
        assert_eq!(OperatingMode::Sanitizing.lifecycle_phase(), LifecyclePhase::Decommission);
    }

    #[test]
    fn two_person_rule_distinct_operators() {
        let op1 = HybridKeyPair::generate().unwrap();
        let op2 = HybridKeyPair::generate().unwrap();
        let c = cmd("EMERGENCY_STOP");
        let data = c.canonical_bytes();
        let s1 = hybrid_sign(&op1, &data).unwrap();
        let s2 = hybrid_sign(&op2, &data).unwrap();
        PolicyEngine::verify_two_person(&c, &op1.public, &s1, &op2.public, &s2).unwrap();
        // один и тот же оператор дважды — отказ
        let s1b = hybrid_sign(&op1, &data).unwrap();
        assert!(PolicyEngine::verify_two_person(&c, &op1.public, &s1, &op1.public, &s1b).is_err());
        // битая вторая подпись — отказ
        let mut bad = s2.clone();
        bad[10] ^= 1;
        assert!(PolicyEngine::verify_two_person(&c, &op1.public, &s1, &op2.public, &bad).is_err());
    }

    #[test]
    fn decommission_3_of_5() {
        let cust: Vec<HybridKeyPair> =
            (0..5).map(|_| HybridKeyPair::generate().unwrap()).collect();
        let ceremony = streebog256(b"decommission-ceremony-node-42");
        let pairs: Vec<(HybridPublicKey, Vec<u8>)> = cust
            .iter()
            .take(3)
            .map(|c| (c.public.clone(), hybrid_sign(c, &ceremony).unwrap()))
            .collect();
        assert_eq!(PolicyEngine::verify_decommission_quorum(&ceremony, &pairs).unwrap(), 3);
        // 2 из 5 — недостаточно (LIFE-005)
        let pairs2: Vec<(HybridPublicKey, Vec<u8>)> = cust
            .iter()
            .take(2)
            .map(|c| (c.public.clone(), hybrid_sign(c, &ceremony).unwrap()))
            .collect();
        assert!(PolicyEngine::verify_decommission_quorum(&ceremony, &pairs2).is_err());
        // дубликат custodian не увеличивает кворум
        let mut pairs3 = pairs2.clone();
        pairs3.push((cust[0].public.clone(), hybrid_sign(&cust[0], &ceremony).unwrap()));
        assert!(PolicyEngine::verify_decommission_quorum(&ceremony, &pairs3).is_err());
    }

    #[test]
    fn policy_hash_stable_and_sensitive() {
        let d1 = PolicyDoc::default();
        let mut d2 = PolicyDoc::default();
        assert_eq!(d1.policy_hash(), d2.policy_hash());
        d2.autonomy_max = 2;
        assert_ne!(d1.policy_hash(), d2.policy_hash());
    }

    #[test]
    fn model_allowlist_bc35() {
        let mut doc = PolicyDoc::default();
        let h = [0xAB; 64];
        assert!(!PolicyEngine::new(doc.clone(), OperatingMode::Normal).model_allowed(&h));
        doc.model_allowlist.push(h);
        assert!(PolicyEngine::new(doc, OperatingMode::Normal).model_allowed(&h));
    }
}
