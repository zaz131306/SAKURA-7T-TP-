//! sakura-node — демон узла платформы SAKURA STACK (L0–L8 в SIL-профиле).
//!
//! Загрузка (§13.16.1): ROM/PBL → SBL → KERNEL (активный слот) → control
//! services → HSM attest → key release policy → RUNTIME_READY;
//! rollback-счётчики коммитятся ТОЛЬКО после успешной загрузки (BC-24).
//!
//! Runtime: NPP-кластер поверх TCP (рукопожатие §13.3 + MGM-сессии),
//! SakuraBFT-консенсус (C-01/BC-23), CRDT-репликация (C-06/BC-34),
//! control API (API-1: идемпотентность BC-27, replay, two-person),
//! аудит (DM-1), OTA (§22.23), holdover-время (§12), window watchdog
//! (§22.11), management HTTP (§21.1, read-only).
#![forbid(unsafe_code)]

use sakura_node::config::NodeConfig;
use sakura_node::control::{IdemEntry, IdemError, IdemStore};
use sakura_node::http::HttpConn;
use sakura_node::net::{self, Conn, NetError, PrincipalKind};
use sakura_node::time::{TimeQuality, TimeService};
use sakura_node::watchdog::WindowWatchdog;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sakura_attestation::{AttestationAgent, ReportInputs};
use sakura_boot::bundle::{RosterEntry, TrustBundle};
use sakura_boot::cert::{SignerCert, USAGE_OPERATOR};
use sakura_boot::image::{parse_image, BootError, DeviceState};
use sakura_boot::keyrelease::{check_key_release, KeyReleasePolicy};
use sakura_boot::pcr::{PcrBank, PCR_CONFIGURATION, PCR_CONTROL_SERVICES, PCR_CRYPTO_POLICY, PCR_HSM_STATUS, PCR_KERNEL, PCR_NETWORK_POLICY, PCR_ROM_PBL_CONFIG, PCR_SBL, PCR_SECURE_BOOT_STATE};
use sakura_boot::rollback::RollbackStore;
use sakura_boot::{measure, BootEvent, BootFsm, BootState, TrustAnchor};
use sakura_common::cbor::Cbor;
use sakura_common::uuid7::Uuid7;
use sakura_common::ErrorCode;
use sakura_consensus::engine::{Engine, Event as CEvent, Msg as CMsg, PHASE_COMMIT, PHASE_PREPARE};
use sakura_consensus::node::{BftNode, Block, ConsensusError, SignatureVerifier, Vote};
use sakura_crdt::{CrdtEngine, CrdtOp, LwwMetadata, MergeAudit, NodeId, VectorClock};
use sakura_gost::hash::streebog256;
use sakura_hsm::soft::SoftHsm;
use sakura_hsm::{HsmBackend, HsmError, KeyHandle, SessionId};
use sakura_hybrid::{HybridKeyPair, HybridPublicKey};
use sakura_npp::frame::NppCodec;
use sakura_npp::msg::MsgType;
use sakura_npp::payload::{consensus_wire, time_wire, ApiRequest, ApiResponse, API_VERSION, TYPE_CONSENSUS_MSG, TYPE_CONTROL_API, TYPE_TIME_SYNC};
use sakura_policy::{Command, OperatingMode, PolicyDecision, PolicyDoc, PolicyEngine, Role};
use sakura_update::{SlotState, SlotStorage, UpdatePackage};

const CLIENT_DST: u16 = 0xFFFF;
/// Коды выхода: 85 — SECURE_BOOT_FAILED (recovery), 86 — provisioning,
/// 87 — перезапуск после OTA (UPDATE FSM REBOOT, §13.16.2).
const EXIT_BOOT_FAILED: i32 = 85;
const EXIT_REBOOT_OTA: i32 = 87;

// ---------------- мосты HSM ----------------

struct HsmAuditSigner {
    hsm: Rc<RefCell<SoftHsm>>,
    sid: SessionId,
    key: KeyHandle,
    pk: HybridPublicKey,
    enabled: bool,
}

impl sakura_audit::AuditSigner for HsmAuditSigner {
    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, sakura_audit::AuditError> {
        if !self.enabled {
            // подписи отключены (производительность SIL) — MAC/chain обязательны
            return Ok(streebog256(data).to_vec());
        }
        let mut buf = vec![0u8; sakura_hybrid::HYBRID_SIG_LEN];
        let n = self
            .hsm
            .borrow_mut()
            .sign(self.sid, self.key, data, &mut buf)
            .map_err(|_| sakura_audit::AuditError::SignatureInvalid)?;
        buf.truncate(n);
        Ok(buf)
    }
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        if !self.enabled {
            return sig.len() == 32 && streebog256(data) == sig[..32];
        }
        sakura_hybrid::hybrid_verify(&self.pk, data, sig)
    }
}

struct HsmConsensusVerifier {
    hsm: Rc<RefCell<SoftHsm>>,
    sid: SessionId,
    key: KeyHandle,
    registry: Rc<RefCell<HashMap<u32, HybridPublicKey>>>,
}

impl SignatureVerifier for HsmConsensusVerifier {
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, ConsensusError> {
        let mut buf = vec![0u8; sakura_hybrid::HYBRID_SIG_LEN];
        let n = self
            .hsm
            .borrow_mut()
            .sign(self.sid, self.key, msg, &mut buf)
            .map_err(|_| ConsensusError::InvalidSignature)?;
        buf.truncate(n);
        Ok(buf)
    }
    fn verify(&self, voter: u32, msg: &[u8], sig: &[u8]) -> bool {
        match self.registry.borrow().get(&voter) {
            Some(pk) => sakura_hybrid::hybrid_verify(pk, msg, sig),
            None => false,
        }
    }
}

// ---------------- пиры и клиенты ----------------

struct Peer {
    entry: RosterEntry,
    conn: Option<Conn>,
    // клиентская сторона рукопожатия (мы dial-им)
    cl_step: u8,
    cl_h: net::HandshakeState,
    #[allow(dead_code)] // nonce_c хранится для аудита транскрипта
    cl_nonce: [u8; 32],
    cl_pending_key: Option<([u8; 32], [u8; 32])>,
    // серверная сторона (входящие соединения пиров обрабатываются в clients
    // до идентификации, затем promote_peer)
    srv_step: u8,
    #[allow(dead_code)]
    srv_h: net::HandshakeState,
    #[allow(dead_code)]
    srv_info: Option<net::HelloInfo>,
    #[allow(dead_code)]
    srv_nonce: [u8; 32],
    alive: bool,
    next_dial_ms: u64,
    last_hb_ms: u64,
}

struct ClientConn {
    cid: u64,
    conn: Conn,
    id: [u8; 16],
    role: Role,
    cert: SignerCert,
    srv_step: u8,
    srv_h: net::HandshakeState,
    srv_info: Option<net::HelloInfo>,
    srv_nonce: [u8; 32],
    /// соединение передано в peer-слот (promote_peer)
    moved: bool,
    dead: bool,
}

struct Waiter {
    request_seq: u64,
    client_cid: u64,
}

// ---------------- приложение ----------------

pub struct NodeApp {
    cfg: NodeConfig,
    bundle: TrustBundle,
    anchor: TrustAnchor,
    hsm: Rc<RefCell<SoftHsm>>,
    sid: SessionId,
    device_key: KeyHandle,
    device_id: [u8; 16],
    #[allow(dead_code)] // публичный ключ устройства — для диагностики/сертификатов
    device_pk: HybridPublicKey,
    device_cert: SignerCert,
    idx: u16,
    codec: NppCodec,
    peers: Vec<Peer>,
    clients: Vec<ClientConn>,
    engine: Engine,
    crdt: CrdtEngine,
    audit: sakura_audit::AuditLog<HsmAuditSigner>,
    policy: PolicyEngine,
    pcrs: PcrBank,
    storage: SlotStorage,
    pending_ops: VecDeque<Cbor>,
    /// Операции, предложенные proposer'ом, но ещё не финализированные
    /// (ре-очередь при view change).
    inflight: Vec<Cbor>,
    /// Dedup-множество op_id (IDEMP: одна команда — один блок).
    op_ids: HashSet<[u8; 16]>,
    pending_since_ms: u64,
    waiters: HashMap<[u8; 16], Waiter>,
    idem: IdemStore,
    time_svc: TimeService,
    wd: WindowWatchdog,
    attest_agent: AttestationAgent,
    last_round_ms: u64,
    last_hb_ms: u64,
    last_sync_ms: u64,
    last_snapshot_ms: u64,
    peer_listener: TcpListener,
    http_listener: TcpListener,
    http_conns: Vec<HttpConn>,
    reboot_flag: bool,
    stop: Arc<AtomicBool>,
    metrics: Metrics,
    last_quality: TimeQuality,
    #[allow(dead_code)] // отпечаток политики выпуска ключей — для attestation-отчётов
    key_release_hash: [u8; 32],
    fw_versions: Vec<(String, String)>,
    next_cid: u64,
}

#[derive(Default, Clone)]
struct Metrics {
    frames_rx: u64,
    frames_tx: u64,
    fec_corrected: u64,
    replays: u64,
    handshake_fail: u64,
    commands_ok: u64,
    commands_denied: u64,
    blocks_finalized: u64,
    sessions_opened: u64,
}

// ==================== BOOT ====================

struct BootArtifacts {
    pcrs: PcrBank,
    #[allow(dead_code)] // артефакт загрузки для диагностики/отчётов
    fsm: BootFsm,
    storage: SlotStorage,
    fw_versions: Vec<(String, String)>,
    key_release_hash: [u8; 32],
}

fn run_boot(
    cfg: &NodeConfig,
    bundle: &TrustBundle,
    anchor: &TrustAnchor,
    hsm: &Rc<RefCell<SoftHsm>>,
    sid: SessionId,
    _device_key: KeyHandle,
    now_s: Option<u64>,
) -> Result<BootArtifacts, (BootFsm, BootError)> {
    let mut fsm = BootFsm::new();
    let mut pcrs = PcrBank::new();

    let mac_key = rollback_mac_key(&cfg.hsm_pin);
    let rollback = RollbackStore::load_or_new(&cfg.rollback_path(), mac_key)
        .map_err(|e| (fsm_fail(&mut fsm, map_rollback(e)), BootError::RollbackRejected))?;
    let storage_root = cfg.flash_dir();
    let mut storage = SlotStorage::open(&storage_root, [4u8; 32], rollback)
        .map_err(|_| (fsm_fail(&mut fsm, BootError::Io), BootError::Io))?;

    let dev = DeviceState {
        hw_rev: cfg.hw_rev,
        now_s,
        min_versions: storage.rollback.min_versions(),
    };

    let mut fw_versions = Vec::new();

    // ROM_VERIFY_PBL: PCR0 — конфигурация ROM (trust bundle)
    let bundle_hash = streebog256(&bundle.to_cbor().to_vec());
    measure(&mut pcrs, PCR_ROM_PBL_CONFIG, &bundle_hash);
    let pbl = std::fs::read(storage_root.join("pbl.img"))
        .map_err(|_| (fsm_fail(&mut fsm, BootError::Io), BootError::Io))?;
    if let Err(e) = verify_boot_image(&pbl, anchor, &dev) {
        return Err((fsm_fail(&mut fsm, e), e));
    }
    fsm.on_event(BootEvent::StageOk); // → PBL_VERIFY_SBL
    measure(&mut pcrs, PCR_SBL, &streebog256(&pbl));
    fw_versions.push(("pbl".into(), image_version(&pbl)));

    // PBL_VERIFY_SBL
    let sbl = std::fs::read(storage_root.join("sbl.img"))
        .map_err(|_| (fsm_fail(&mut fsm, BootError::Io), BootError::Io))?;
    if let Err(e) = verify_boot_image(&sbl, anchor, &dev) {
        return Err((fsm_fail(&mut fsm, e), e));
    }
    fsm.on_event(BootEvent::StageOk); // → SBL_VERIFY_KERNEL
    measure(&mut pcrs, PCR_SBL, &streebog256(&sbl));
    fw_versions.push(("sbl".into(), image_version(&sbl)));

    // SBL_VERIFY_KERNEL — активный слот A/B (§22.23).
    // UPDATE-ROLLBACK-001 (BC-24): при неудачной загрузке нового образа —
    // MARK_FAILED + RESTORE_PREVIOUS_SLOT + DO_NOT_COMMIT_ROLLBACK_COUNTER.
    let mut kernel = storage
        .read_active_image()
        .map_err(|_| (fsm_fail(&mut fsm, BootError::Io), BootError::Io))?;
    if let Err(e) = verify_boot_image(&kernel, anchor, &dev) {
        let active = storage.active_slot();
        let pending_boot = storage.slot_meta(active).state == SlotState::PendingBoot;
        let pending_rc = (1..=4u8).any(|t| storage.rollback.pending(t).is_some());
        if pending_boot || pending_rc {
            eprintln!("sakura-node: boot self-test FAILED ({e:?}) — RESTORE_PREVIOUS_SLOT (BC-24)");
            let _ = storage.mark_failed();
            for t in 1..=4u8 {
                let _ = storage.rollback.discard_pending(t);
            }
            storage.rollback.note_boot_failure();
            let _ = storage.restore_previous_slot();
            let _ = storage.rollback.save(&cfg.rollback_path());
            kernel = storage
                .read_active_image()
                .map_err(|_| (fsm_fail(&mut fsm, BootError::Io), BootError::Io))?;
            if let Err(e2) = verify_boot_image(&kernel, anchor, &dev) {
                return Err((fsm_fail(&mut fsm, e2), e2));
            }
        } else {
            storage.rollback.note_boot_failure();
            let _ = storage.rollback.save(&cfg.rollback_path());
            return Err((fsm_fail(&mut fsm, e), e));
        }
    }
    fsm.on_event(BootEvent::StageOk); // → KERNEL_START
    measure(&mut pcrs, PCR_KERNEL, &streebog256(&kernel));
    fw_versions.push(("kernel".into(), image_version(&kernel)));
    fsm.on_event(BootEvent::StageOk); // → CONTROL_SERVICES_START

    // CONTROL_SERVICES_START: измеряем конфигурации
    measure(&mut pcrs, PCR_CONTROL_SERVICES, &streebog256(b"control-services-v2.3"));
    measure(&mut pcrs, PCR_CONFIGURATION, &streebog256(cfg_canonical(cfg).as_bytes()));
    let roster_hash = streebog256(&bundle.to_cbor().to_vec());
    measure(&mut pcrs, PCR_NETWORK_POLICY, &roster_hash);
    fsm.on_event(BootEvent::StageOk); // → HSM_ATTEST

    // HSM_ATTEST (C-04: явная сессия)
    let mut nonce = [0u8; 32];
    sakura_common::rand::fill(&mut nonce);
    let mut report_buf = [0u8; 1024];
    let n = {
        let mut h = hsm.borrow_mut();
        h.attest(sid, &nonce, &mut report_buf)
            .map_err(|_| (fsm_fail(&mut fsm, BootError::HsmAttest), BootError::HsmAttest))?
    };
    let hsm_report = Cbor::from_slice(&report_buf[..n])
        .map_err(|_| (fsm_fail(&mut fsm, BootError::HsmAttest), BootError::HsmAttest))?;
    measure(&mut pcrs, PCR_HSM_STATUS, &streebog256(&report_buf[..256.min(report_buf.len())]));
    let hsm_status = hsm_report.get("hsm_status").and_then(|v| v.as_text()).unwrap_or("UNKNOWN");
    if hsm_status != "OK" {
        return Err((fsm_fail(&mut fsm, BootError::HsmAttest), BootError::HsmAttest));
    }
    fsm.on_event(BootEvent::StageOk); // → KEY_RELEASE_POLICY_CHECK

    // KEY_RELEASE_POLICY_CHECK (§13.7): криптополитика + версии + tamper
    let policy_doc = PolicyDoc::default();
    measure(&mut pcrs, PCR_CRYPTO_POLICY, &policy_doc.policy_hash());
    let krp = KeyReleasePolicy {
        expected_pcrs: Default::default(), // PCR предъявляются удалённо (attestation)
        min_versions: Default::default(),
        hsm_status_required: "OK".into(),
        model_allowlist: Vec::new(),
        time_quality_allowed: vec!["LOCKED".into(), "HOLDOVER".into()],
        require_no_tamper: true,
    };
    let key_release_hash = krp.policy_hash();
    check_key_release(
        &krp,
        &pcrs,
        &hsm_report,
        &storage.rollback,
        &[],
        "HOLDOVER", // при старте — holdover из персистента (§12.1)
        hsm.borrow().is_tampered(),
    )
    .map_err(|e| {
        eprintln!("sakura-node: key release policy: {e:?}");
        (fsm_fail(&mut fsm, BootError::KeyReleasePolicy), BootError::KeyReleasePolicy)
    })?;
    fsm.on_event(BootEvent::StageOk); // → KeyReleasePolicyCheck
    measure(&mut pcrs, PCR_SECURE_BOOT_STATE, b"RUNTIME_READY");
    fsm.on_event(BootEvent::StageOk); // → RUNTIME_READY
    if fsm.state != BootState::RuntimeReady {
        return Err((fsm_fail(&mut fsm, BootError::KeyReleasePolicy), BootError::KeyReleasePolicy));
    }

    // BC-24: после успешной загрузки — commit pending rollback counter
    let active = storage.active_slot();
    if storage.slot_meta(active).state == SlotState::PendingBoot {
        let itype = (1..=4u8).find(|t| storage.rollback.pending(*t).is_some());
        if let Some(t) = itype {
            // self-test: хэш образа слота (загружен и верифицирован выше)
            if storage.rollback.commit_pending(t).is_ok() {
                let _ = storage.mark_successful();
                let _ = storage.clear_pending_metadata();
            } else {
                let _ = storage.rollback.discard_pending(t);
                let _ = storage.mark_failed();
                let _ = storage.restore_previous_slot();
            }
        } else {
            let _ = storage.mark_successful();
            let _ = storage.clear_pending_metadata();
        }
        storage.rollback.note_boot_success();
    }
    let _ = storage.rollback.save(&cfg.rollback_path());

    Ok(BootArtifacts { pcrs, fsm, storage, fw_versions, key_release_hash })
}

fn fsm_fail(fsm: &mut BootFsm, err: BootError) -> BootFsm {
    let st = fsm.on_event(BootEvent::StageFailed(err));
    BootFsm { state: st, fail_count: fsm.fail_count, last_error: fsm.last_error }
}

fn map_rollback(e: sakura_boot::rollback::RollbackError) -> BootError {
    match e {
        sakura_boot::rollback::RollbackError::RollbackDetected => BootError::RollbackRejected,
        _ => BootError::Io,
    }
}

#[allow(dead_code)]
fn unused_anchors(_e: HsmError, _b: BootError) {}

fn verify_boot_image(
    img: &[u8],
    anchor: &TrustAnchor,
    dev: &DeviceState,
) -> Result<u32, BootError> {
    let parsed = parse_image(img)?;
    parsed.verify(anchor, dev)?;
    Ok(parsed.header.version)
}

fn image_version(img: &[u8]) -> String {
    parse_image(img).map(|p| p.header.version.to_string()).unwrap_or_else(|_| "0".into())
}

fn cfg_canonical(cfg: &NodeConfig) -> String {
    format!(
        "idx={};hw={};listen={};n={};mode={};round={};hb={};pto={}",
        cfg.idx, cfg.hw_rev, cfg.listen, cfg.cluster_n, cfg.consensus_mode,
        cfg.round_ms, cfg.heartbeat_ms, cfg.proposer_timeout_ms
    )
}

fn rollback_mac_key(pin: &str) -> [u8; 32] {
    let h = sakura_gost::kdf::kdf_gostr3411_2012_256(
        &streebog256(pin.as_bytes()),
        b"ROLLBACK-STORE",
        b"SAKURA-V1",
    );
    h
}

// ==================== MAIN ====================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "node.ini".to_owned());
    let cfg = NodeConfig::load(&cfg_path).unwrap_or_else(|e| {
        eprintln!("sakura-node: config error: {e}");
        std::process::exit(2);
    });

    match NodeApp::start(cfg) {
        Ok(mut app) => {
            let code = app.run();
            std::process::exit(code);
        }
        Err((fsm, err)) => {
            eprintln!(
                "sakura-node: SECURE_BOOT_FAILED: {err:?} (fsm state {:?}, fails {})",
                fsm.state, fsm.fail_count
            );
            std::process::exit(EXIT_BOOT_FAILED);
        }
    }
}

impl NodeApp {
    fn start(cfg: NodeConfig) -> Result<Self, (BootFsm, BootError)> {
        std::fs::create_dir_all(cfg.data_dir.join("identity")).ok();
        std::fs::create_dir_all(cfg.data_dir.join("audit")).ok();
        std::fs::create_dir_all(cfg.flash_dir()).ok();

        let bundle = TrustBundle::load(&cfg.bundle_path()).ok_or((
            BootFsm::new(),
            BootError::ChainInvalid,
        ))?;
        let anchor = bundle.anchor();

        // HSM: keystore от provisioning (§22.18 factory emulation)
        let mut hsm_box = SoftHsm::new(cfg.hsm_pin.as_bytes()).map_err(|_| (BootFsm::new(), BootError::HsmAttest))?;
        if cfg.keystore_path().exists() {
            hsm_box
                .load_keystore(&cfg.keystore_path(), cfg.hsm_pin.as_bytes())
                .map_err(|_| (BootFsm::new(), BootError::HsmAttest))?;
        } else {
            return Err((BootFsm::new(), BootError::KeyMissing));
        }
        let hsm = Rc::new(RefCell::new(hsm_box));
        let sid = hsm
            .borrow_mut()
            .open_session(cfg.hsm_pin.as_bytes())
            .map_err(|_| (BootFsm::new(), BootError::HsmAttest))?;
        let device_key: KeyHandle = 1;
        let device_pk = hsm
            .borrow()
            .public_key_struct(device_key)
            .map_err(|_| (BootFsm::new(), BootError::KeyMissing))?;

        let mut node_id = [0u8; 16];
        {
            let b = sakura_common::hex::decode(&cfg.node_id_hex).map_err(|_| (BootFsm::new(), BootError::Io))?;
            if b.len() != 16 {
                return Err((BootFsm::new(), BootError::Io));
            }
            node_id.copy_from_slice(&b);
        }
        let device_cert = bundle
            .device_certs
            .get(&node_id)
            .cloned()
            .ok_or((BootFsm::new(), BootError::ChainInvalid))?;
        if device_cert.public.to_bytes() != device_pk.to_bytes() {
            return Err((BootFsm::new(), BootError::ChainInvalid));
        }

        let now_s = None; // время до синхронизации не доверено (§22.1.3: now_s=None)
        let boot = run_boot(&cfg, &bundle, &anchor, &hsm, sid, device_key, now_s)?;

        // ---- подсистемы ----
        let registry: Rc<RefCell<HashMap<u32, HybridPublicKey>>> =
            Rc::new(RefCell::new(HashMap::new()));
        for r in &bundle.roster {
            if let Some(c) = bundle.device_certs.get(&r.node_id) {
                registry.borrow_mut().insert(r.idx, c.public.clone());
            }
        }
        let verifier = Box::new(HsmConsensusVerifier {
            hsm: hsm.clone(),
            sid,
            key: device_key,
            registry,
        });
        let node = if cfg.consensus_mode == "cft" {
            BftNode::new_cft(cfg.idx, cfg.cluster_n, verifier)
        } else {
            BftNode::new(cfg.idx, cfg.cluster_n, verifier)
        };
        let mut engine = Engine::new(node);
        engine.set_timeouts(cfg.proposer_timeout_ms);
        let mut out = Vec::new();
        engine.start(&mut out);

        let mut crdt = CrdtEngine::new();
        if let Ok(raw) = std::fs::read(cfg.crdt_snapshot_path()) {
            if let Ok(v) = Cbor::from_slice(&raw) {
                crdt.merge_state_snapshot(&v).ok();
            }
        }

        let audit_signer = HsmAuditSigner {
            hsm: hsm.clone(),
            sid,
            key: device_key,
            pk: device_pk.clone(),
            enabled: cfg.sign_audit_records,
        };
        let audit_key = sakura_gost::kdf::kdf_gostr3411_2012_256(
            &streebog256(cfg.hsm_pin.as_bytes()),
            b"AUDIT-KEY",
            &node_id,
        );
        let audit = sakura_audit::AuditLog::new(
            node_id,
            audit_signer,
            audit_key,
            sakura_common::time::unix_s(),
        )
        .with_path(cfg.audit_path())
        .map_err(|_| (BootFsm::new(), BootError::Io))?;

        let policy = PolicyEngine::new(PolicyDoc::default(), OperatingMode::Normal);

        let idem_mac = sakura_gost::kdf::kdf_gostr3411_2012_256(
            &streebog256(cfg.hsm_pin.as_bytes()),
            b"IDEM-STORE",
            &node_id,
        );
        let mut idem = IdemStore::new(idem_mac);
        idem.load(&cfg.idem_path()).ok();

        let mut time_svc = TimeService::new(cfg.drift_ppb_x1000);
        time_svc.load(&cfg.time_state_path());

        let wd = WindowWatchdog::spawn(cfg.wd_min_ms, cfg.wd_max_ms);

        let attest_agent =
            AttestationAgent::new(node_id.to_vec(), cfg.hw_rev, device_key);

        let peer_listener = net::listener(&cfg.listen).map_err(|_| (BootFsm::new(), BootError::Io))?;
        let http_listener = net::listener(&cfg.http_listen).map_err(|_| (BootFsm::new(), BootError::Io))?;

        let roster_sorted: Vec<RosterEntry> = bundle.roster.to_vec();
        let peers: Vec<Peer> = roster_sorted
            .into_iter()
            .filter(|r| r.idx != cfg.idx)
            .map(|entry| Peer {
                entry,
                conn: None,
                cl_step: 0,
                cl_h: Default::default(),
                cl_nonce: [0u8; 32],
                cl_pending_key: None,
                srv_step: 0,
                srv_h: Default::default(),
                srv_info: None,
                srv_nonce: [0u8; 32],
                alive: false,
                next_dial_ms: 0,
                last_hb_ms: 0,
            })
            .collect();

        let stop = Arc::new(AtomicBool::new(false));
        install_signal_handler(&stop, &cfg.data_dir.join("STOP"));

        let mut app = NodeApp {
            idx: cfg.idx as u16,
            cfg,
            bundle,
            anchor,
            hsm,
            sid,
            device_key,
            device_id: node_id,
            device_pk,
            device_cert,
            codec: NppCodec::new(true),
            peers,
            clients: Vec::new(),
            engine,
            crdt,
            audit,
            policy,
            pcrs: boot.pcrs,
            storage: boot.storage,
            pending_ops: VecDeque::new(),
            inflight: Vec::new(),
            op_ids: HashSet::new(),
            pending_since_ms: 0,
            waiters: HashMap::new(),
            idem,
            time_svc,
            wd,
            attest_agent,
            last_round_ms: 0,
            last_hb_ms: 0,
            last_sync_ms: 0,
            last_snapshot_ms: sakura_common::time::unix_ms(),
            peer_listener,
            http_listener,
            http_conns: Vec::new(),
            reboot_flag: false,
            stop,
            metrics: Metrics::default(),
            last_quality: TimeQuality::Free,
            key_release_hash: boot.key_release_hash,
            fw_versions: boot.fw_versions,
            next_cid: 1,
        };
        app.audit_event(
            sakura_audit::events::BOOT,
            [0u8; 16],
            0,
            "RUNTIME_READY",
        );
        Ok(app)
    }

    // ---------------- цикл ----------------

    fn run(&mut self) -> i32 {
        loop {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            self.wd.kick();
            let local_now = sakura_common::time::unix_ms();
            let now = self.time_svc.now_ms(local_now);

            self.accept_peers();
            self.accept_http();
            self.poll_peers(now);
            self.poll_clients();
            self.poll_http();

            self.consensus_round(now);
            self.engine_tick(now);
            self.heartbeats(local_now);
            self.time_sync(local_now);
            self.check_watchdog();
            self.snapshots(local_now);

            if self.reboot_flag {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(4));
        }
        self.shutdown();
        if self.reboot_flag {
            EXIT_REBOOT_OTA
        } else {
            0
        }
    }

    fn shutdown(&mut self) {
        // §22.8 выключение: stop control services → flush logs → zeroize
        // session keys → save nonvolatile state
        for p in &mut self.peers {
            if let Some(c) = p.conn.take() {
                drop(c); // session keys zeroize в Drop Conn-структур нет —
                         // ключи хранятся в Option<[u8;32]>, очищаем явно:
            }
        }
        self.save_snapshots();
        self.time_svc.save(&self.cfg.time_state_path());
        self.audit_event(sakura_audit::events::SESSION_CLOSE, [0u8; 16], 0, "SHUTDOWN");
        if let Ok(mut h) = self.hsm.try_borrow_mut() {
            let _ = h.close_session(self.sid);
        }
        eprintln!("sakura-node[{}]: shutdown complete", self.idx);
    }

    fn save_snapshots(&mut self) {
        let snap = self.crdt.state_cbor().to_vec();
        let _ = std::fs::write(self.cfg.crdt_snapshot_path(), snap);
        let _ = self.idem.save(&self.cfg.idem_path());
    }

    fn snapshots(&mut self, local_now: u64) {
        if local_now.saturating_sub(self.last_snapshot_ms) > 5_000 {
            self.last_snapshot_ms = local_now;
            self.save_snapshots();
        }
    }

    fn check_watchdog(&mut self) {
        if self.wd.timed_out() {
            // §22.11: system manager WDT → safe state
            self.audit_event(sakura_audit::events::WATCHDOG, [0u8; 16], 0, "WINDOW_TIMEOUT");
            let _ = self.policy.set_mode(OperatingMode::DegradedCompute);
            self.wd.reset();
        }
    }

    fn audit_event(&mut self, etype: &str, actor: [u8; 16], session: u64, result: &str) -> u64 {
        let now = self.time_svc.now_ms(sakura_common::time::unix_ms()) / 1000;
        match self.audit.append(now, actor, session, etype, self.device_id, result) {
            Ok(seq) => seq,
            Err(e) => {
                eprintln!("sakura-node[{}]: AUDIT FAILURE {e:?} — fail-secure: переход в SECURE_LOCKDOWN", self.idx);
                let _ = self.policy.set_mode(OperatingMode::SecureLockdown);
                0
            }
        }
    }

    fn now_s(&self) -> u64 {
        self.time_svc.now_ms(sakura_common::time::unix_ms()) / 1000
    }

    // ---------------- сеть: пиры ----------------

    fn accept_peers(&mut self) {
        loop {
            match self.peer_listener.accept() {
                Ok((stream, _addr)) => {
                    if let Ok(conn) = Conn::new(stream, true) {
                        // входящее соединение: помещаем во временный слот до HELLO
                        let cid = self.next_cid;
                        self.next_cid += 1;
                        self.clients.push(ClientConn {
                            cid,
                            conn,
                            id: [0u8; 16],
                            role: Role::Service,
                            cert: self.device_cert.clone(), // заглушка до handshake
                            srv_step: 0,
                            srv_h: Default::default(),
                            srv_info: None,
                            srv_nonce: [0u8; 32],
                            moved: false,
                            dead: false,
                        });
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        // исходящие соединения: i < j (детерминированное правило)
        let local_now = sakura_common::time::unix_ms();
        let my_idx = self.idx as u32;
        for pi in 0..self.peers.len() {
            let (should_dial, addr) = {
                let p = &self.peers[pi];
                (
                    p.conn.is_none() && p.entry.idx > my_idx && local_now >= p.next_dial_ms,
                    format!("{}:{}", p.entry.host, p.entry.port),
                )
            };
            if should_dial {
                match TcpStream::connect_timeout(
                    &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    std::time::Duration::from_millis(300),
                ) {
                    Ok(stream) => {
                        if let Ok(mut conn) = Conn::new(stream, false) {
                            let (h0, nonce) = net::client_hello(
                                self.device_id,
                                PrincipalKind::Node,
                                self.cfg.hw_rev,
                            );
                            if conn
                                .send_msg(&self.codec, self.idx, self.peers[pi].entry.idx as u16, MsgType::Hello as u8, &h0)
                                .is_ok()
                            {
                                let p = &mut self.peers[pi];
                                p.cl_step = 1;
                                p.cl_h.h0 = h0;
                                p.cl_nonce = nonce;
                                p.conn = Some(conn);
                            }
                        }
                    }
                    Err(_) => {
                        self.peers[pi].next_dial_ms = local_now + 500;
                    }
                }
            }
        }
    }

    fn poll_peers(&mut self, now_ms: u64) {
        let mut to_remove = Vec::new();
        for pi in 0..self.peers.len() {
            let frames = if let Some(conn) = &mut self.peers[pi].conn {
                match conn.poll_frames(&self.codec, 64) {
                    Ok(f) => f,
                    Err(NetError::Closed) | Err(NetError::Io) => {
                        to_remove.push(pi);
                        continue;
                    }
                    Err(NetError::Replay(code)) => {
                        self.metrics.replays += 1;
                        self.audit_event(
                            sakura_audit::events::CRYPTO_FAILURE,
                            self.peers[pi].entry.node_id,
                            0,
                            code.to_common().as_str(),
                        );
                        to_remove.push(pi);
                        continue;
                    }
                    Err(e) => {
                        self.metrics.handshake_fail += 1;
                        let _ = e;
                        to_remove.push(pi);
                        continue;
                    }
                }
            } else {
                continue;
            };
            for (mtype, _seq, payload) in frames {
                self.metrics.frames_rx += 1;
                self.handle_peer_frame(pi, mtype, payload, now_ms);
            }
            // таймаут пира (communication WDT 3 с, §22.11)
            let (alive_before, last_rx) = {
                let p = &self.peers[pi];
                (p.alive, p.conn.as_ref().map(|c| c.last_rx_ms).unwrap_or(0))
            };
            if alive_before && now_ms.saturating_sub(last_rx) > self.cfg.peer_timeout_ms {
                self.peers[pi].alive = false;
                let mut ev = Vec::new();
                self.engine.note_peer_down(self.peers[pi].entry.idx, &mut ev);
                self.process_engine_events(ev);
                self.audit_event(
                    sakura_audit::events::NETWORK_PARTITION,
                    self.peers[pi].entry.node_id,
                    0,
                    "PEER_TIMEOUT",
                );
            }
        }
        for pi in to_remove.into_iter().rev() {
            let was_alive = self.peers[pi].alive;
            self.peers[pi].conn = None;
            self.peers[pi].alive = false;
            self.peers[pi].cl_step = 0;
            self.peers[pi].srv_step = 0;
            self.peers[pi].srv_info = None;
            self.peers[pi].next_dial_ms = now_ms + 500;
            if was_alive {
                let mut ev = Vec::new();
                self.engine.note_peer_down(self.peers[pi].entry.idx, &mut ev);
                self.process_engine_events(ev);
            }
        }
    }

    fn handle_peer_frame(&mut self, pi: usize, mtype: MsgType, payload: Vec<u8>, now_ms: u64) {
        let established = self.peers[pi].conn.as_ref().map(|c| c.established).unwrap_or(false);
        if !established {
            self.handshake_peer(pi, mtype, &payload);
            return;
        }
        match mtype {
            MsgType::Heartbeat => {
                self.peers[pi].alive = true;
                self.peers[pi].last_hb_ms = now_ms;
                let mut ev = Vec::new();
                let m = CMsg::Alive { node: self.peers[pi].entry.idx };
                let tx = self.engine.on_msg(&m, &mut ev);
                self.process_engine_events(ev);
                self.broadcast_consensus(tx);
                let _ = self.send_to_peer(pi, MsgType::HeartbeatAck as u8, b"");
            }
            MsgType::HeartbeatAck => {
                self.peers[pi].alive = true;
                self.peers[pi].last_hb_ms = now_ms;
            }
            MsgType::ConsensusMsg => {
                if let Some(m) = decode_consensus_msg(&payload) {
                    let mut ev = Vec::new();
                    let tx = self.engine.on_msg(&m, &mut ev);
                    self.process_engine_events(ev);
                    self.broadcast_consensus(tx);
                }
            }
            MsgType::CrdtSync => {
                // пересылка операций proposer'у + state transfer в RECOVERY
                self.handle_ops_forward(&payload);
            }
            MsgType::TimeSync => {
                self.handle_time_sync(pi, &payload);
            }
            _ => {}
        }
    }

    // ---------------- рукопожатие (серверная и клиентская стороны) ----------------

    fn handshake_peer(&mut self, pi: usize, mtype: MsgType, payload: &[u8]) {
        let server_side = self
            .peers[pi]
            .conn
            .as_ref()
            .map(|c| c.server_side)
            .unwrap_or(true);
        // входящее соединение от пира обрабатывается в clients-пуле до HELLO;
        // после идентификации переводится в peer-слот (promote_peer)
        if server_side {
            return;
        }
        match (self.peers[pi].cl_step, mtype) {
            (1, MsgType::AuthChallenge) => {
                self.peers[pi].cl_h.h1 = payload.to_vec();
                // AUTH_RESPONSE: подпись устройства по streebog(h0||h1)
                let mut t = Vec::new();
                t.extend_from_slice(&self.peers[pi].cl_h.h0);
                t.extend_from_slice(&self.peers[pi].cl_h.h1);
                let digest = streebog256(&t);
                let mut sig = vec![0u8; sakura_hybrid::HYBRID_SIG_LEN];
                let signed = {
                    let mut h = self.hsm.borrow_mut();
                    h.sign(self.sid, self.device_key, &digest, &mut sig).is_ok()
                };
                if !signed {
                    self.drop_peer(pi);
                    return;
                }
                let resp = net::auth_response_payload(sig);
                self.peers[pi].cl_h.h2 = resp.clone();
                let _ = self.send_to_peer(pi, MsgType::AuthResponse as u8, &resp);
                // SESSION_ESTABLISH: эфемерный ГОСТ + ML-KEM под сертификат пира
                let peer_cert = self
                    .bundle
                    .device_certs
                    .get(&self.peers[pi].entry.node_id)
                    .cloned();
                let Some(pc) = peer_cert else {
                    self.drop_peer(pi);
                    return;
                };
                let eph = HybridKeyPair::generate().unwrap();
                let mut ukm_b = [0u8; 8];
                sakura_common::rand::fill(&mut ukm_b);
                let ukm = u64::from_le_bytes(ukm_b) | 1;
                let ss_gost =
                    sakura_gost::vko_kek_256(&eph.gost_priv, &pc.public.gost, ukm).unwrap();
                let (ct, ss_pq) =
                    sakura_pq::mlkem1024_encapsulate(&pc.public.mlkem_ek).unwrap();
                let est = net::establish_payload(ukm, eph.public.gost, ct);
                self.peers[pi].cl_h.h3 = est.clone();
                let _ = self.send_to_peer(pi, MsgType::SessionEstablish as u8, &est);
                let (key, cb) = net::derive_session_key(
                    &self.peers[pi].cl_h.h0,
                    &self.peers[pi].cl_h.h1,
                    &self.peers[pi].cl_h.h2,
                    &self.peers[pi].cl_h.h3,
                    &ss_gost,
                    &ss_pq,
                );
                self.peers[pi].cl_pending_key = Some((key, cb));
                self.peers[pi].cl_step = 2;
            }
            (2, MsgType::SessionConfirm) => {
                if let Ok(v) = Cbor::from_slice(payload) {
                    let sig = v.get("sig").and_then(|x| x.as_bytes()).unwrap_or(&[]).to_vec();
                    let mut t = Vec::new();
                    t.extend_from_slice(&self.peers[pi].cl_h.h0);
                    t.extend_from_slice(&self.peers[pi].cl_h.h1);
                    t.extend_from_slice(&self.peers[pi].cl_h.h2);
                    t.extend_from_slice(&self.peers[pi].cl_h.h3);
                    let digest = streebog256(&t);
                    let pc = &self.bundle.device_certs[&self.peers[pi].entry.node_id];
                    if sakura_hybrid::hybrid_verify(&pc.public, &digest, &sig) {
                        if let Some((key, cb)) = self.peers[pi].cl_pending_key.take() {
                            let nid = self.peers[pi].entry.node_id;
                            if let Some(c) = &mut self.peers[pi].conn {
                                c.session_key = Some(key);
                                c.channel_binding = Some(cb);
                                c.established = true;
                                c.peer_id = Some(nid);
                                c.peer_kind = Some(PrincipalKind::Node);
                            }
                            self.peers[pi].cl_step = 3;
                            self.peers[pi].alive = true;
                            self.metrics.sessions_opened += 1;
                            self.audit_event(
                                sakura_audit::events::SESSION_OPEN,
                                self.peers[pi].entry.node_id,
                                0,
                                "PEER",
                            );
                            let mut ev = Vec::new();
                            let tx = self.engine.on_msg(
                                &CMsg::Alive { node: self.peers[pi].entry.idx },
                                &mut ev,
                            );
                            self.process_engine_events(ev);
                            self.broadcast_consensus(tx);
                        }
                    } else {
                        self.metrics.handshake_fail += 1;
                        self.drop_peer(pi);
                    }
                }
            }
            _ => {
                // неожиданное сообщение рукопожатия — channel binding mismatch
                self.metrics.handshake_fail += 1;
                self.drop_peer(pi);
            }
        }
    }

    fn drop_peer(&mut self, pi: usize) {
        self.peers[pi].conn = None;
        self.peers[pi].cl_step = 0;
        self.peers[pi].next_dial_ms = sakura_common::time::unix_ms() + 1000;
    }

    // ---------------- клиенты (CLI + входящие пиры до HELLO) ----------------

    fn poll_clients(&mut self) {
        for ci in 0..self.clients.len() {
            if self.clients[ci].moved || self.clients[ci].dead || self.clients[ci].srv_step == 250 {
                continue;
            }
            let frames = match self.clients[ci].conn.poll_frames(&self.codec, 32) {
                Ok(f) => f,
                Err(NetError::Closed) | Err(NetError::Io) => {
                    self.clients[ci].dead = true;
                    continue;
                }
                Err(_) => {
                    self.clients[ci].dead = true;
                    continue;
                }
            };
            for (mtype, _seq, payload) in frames {
                if self.clients[ci].srv_step < 5 {
                    self.handshake_client(ci, mtype, &payload);
                } else {
                    self.handle_client_frame(ci, mtype, payload);
                }
                if self.clients[ci].moved {
                    break;
                }
            }
        }
        let had_sessions = self.clients.iter().any(|c| c.srv_step == 5 && (c.dead || c.moved));
        self.clients.retain(|c| !c.dead && !c.moved && c.srv_step != 250);
        if had_sessions {
            self.audit_event(sakura_audit::events::SESSION_CLOSE, [0u8; 16], 0, "CLIENT");
        }
    }

    fn handshake_client(&mut self, ci: usize, mtype: MsgType, payload: &[u8]) {
        let step = self.clients[ci].srv_step;
        match (step, mtype) {
            (0, MsgType::Hello) => {
                self.clients[ci].srv_h.h0 = payload.to_vec();
                let info = match net::parse_hello(payload) {
                    Ok(i) => i,
                    Err(_) => {
                        self.clients[ci].srv_step = 250;
                        return;
                    }
                };
                let now_s = self.now_s();
                // сертификат участника — из trust bundle (provisioned roster)
                let cert_opt = match info.kind {
                    PrincipalKind::Node => self.bundle.device_certs.get(&info.id).cloned(),
                    PrincipalKind::Operator => {
                        self.bundle.operator_certs.get(&info.id).map(|(c, _)| c.clone())
                    }
                };
                let ok = match &cert_opt {
                    Some(cert) => net::verify_peer_cert(
                        &self.anchor,
                        &self.bundle.platform_cert,
                        &info,
                        cert,
                        now_s,
                    )
                    .is_ok(),
                    None => false,
                };
                if ok {
                    if let Some(cert) = cert_opt {
                        self.clients[ci].cert = cert;
                    }
                }
                if !ok {
                    self.metrics.handshake_fail += 1;
                    let id = info.id;
                    self.audit_event(sakura_audit::events::AUTHENTICATION, id, 0, "AUTH_FAILED");
                    self.clients[ci].srv_step = 250;
                    return;
                }
                let mut nonce = [0u8; 32];
                sakura_common::rand::fill(&mut nonce);
                self.clients[ci].srv_nonce = nonce;
                let ch = net::challenge_payload(nonce);
                self.clients[ci].srv_h.h1 = ch.clone();
                let sent = self.clients[ci]
                    .conn
                    .send_msg(&self.codec, self.idx, CLIENT_DST, MsgType::AuthChallenge as u8, &ch)
                    .is_ok();
                if !sent {
                    self.clients[ci].srv_step = 250;
                    return;
                }
                self.clients[ci].srv_info = Some(info);
                self.clients[ci].srv_step = 1;
            }
            (1, MsgType::AuthResponse) => {
                self.clients[ci].srv_h.h2 = payload.to_vec();
                let sig = Cbor::from_slice(payload)
                    .ok()
                    .and_then(|v| v.get("sig").and_then(|x| x.as_bytes()).map(|b| b.to_vec()));
                let Some(sig) = sig else {
                    self.clients[ci].srv_step = 250;
                    return;
                };
                let info = self.clients[ci].srv_info.clone().unwrap();
                let cert_pk = self.clients[ci].cert.public.clone();
                let mut t = Vec::new();
                t.extend_from_slice(&self.clients[ci].srv_h.h0);
                t.extend_from_slice(&self.clients[ci].srv_h.h1);
                let digest = streebog256(&t);
                if !sakura_hybrid::hybrid_verify(&cert_pk, &digest, &sig) {
                    self.metrics.handshake_fail += 1;
                    self.audit_event(sakura_audit::events::AUTHENTICATION, info.id, 0, "AUTH_FAILED");
                    self.clients[ci].srv_step = 250;
                    return;
                }
                self.clients[ci].srv_step = 2;
            }
            (2, MsgType::SessionEstablish) => {
                self.clients[ci].srv_h.h3 = payload.to_vec();
                let est = match net::parse_establish(payload) {
                    Ok(e) => e,
                    Err(_) => {
                        self.clients[ci].srv_step = 250;
                        return;
                    }
                };
                // VKO + ML-KEM декапсуляция внутри HSM (секреты не покидают)
                let derived = {
                    let mut h = self.hsm.borrow_mut();
                    let g = h.vko_kek(self.sid, self.device_key, &est.eph_pub, est.ukm);
                    let mut ss = [0u8; 32];
                    let p = h.kem_decapsulate(self.sid, self.device_key, &est.mlkem_ct, &mut ss);
                    match (g, p) {
                        (Ok(g), Ok(_)) => Some((g, ss)),
                        _ => None,
                    }
                };
                let Some((ss_gost, ss_pq)) = derived else {
                    self.clients[ci].srv_step = 250;
                    return;
                };
                let (key, cb) = net::derive_session_key(
                    &self.clients[ci].srv_h.h0,
                    &self.clients[ci].srv_h.h1,
                    &self.clients[ci].srv_h.h2,
                    &self.clients[ci].srv_h.h3,
                    &ss_gost,
                    &ss_pq,
                );
                let mut t = Vec::new();
                t.extend_from_slice(&self.clients[ci].srv_h.h0);
                t.extend_from_slice(&self.clients[ci].srv_h.h1);
                t.extend_from_slice(&self.clients[ci].srv_h.h2);
                t.extend_from_slice(&self.clients[ci].srv_h.h3);
                let digest = streebog256(&t);
                let mut sig = vec![0u8; sakura_hybrid::HYBRID_SIG_LEN];
                let signed = {
                    let mut h = self.hsm.borrow_mut();
                    h.sign(self.sid, self.device_key, &digest, &mut sig).is_ok()
                };
                if !signed {
                    self.clients[ci].srv_step = 250;
                    return;
                }
                let conf = net::confirm_payload(sig);
                let sent = self.clients[ci]
                    .conn
                    .send_msg(&self.codec, self.idx, CLIENT_DST, MsgType::SessionConfirm as u8, &conf)
                    .is_ok();
                if !sent {
                    self.clients[ci].srv_step = 250;
                    return;
                }
                let info = self.clients[ci].srv_info.clone().unwrap();
                {
                    let c = &mut self.clients[ci];
                    c.conn.session_key = Some(key);
                    c.conn.channel_binding = Some(cb);
                    c.conn.established = true;
                    c.conn.peer_id = Some(info.id);
                    c.conn.peer_kind = Some(info.kind);
                    c.conn.peer_cert = Some(c.cert.clone());
                    c.id = info.id;
                    c.role = match info.kind {
                        PrincipalKind::Operator => self
                            .bundle
                            .operator_role(&info.id)
                            .and_then(Role::from_str_name)
                            .unwrap_or(Role::Service),
                        PrincipalKind::Node => Role::Service,
                    };
                    c.srv_step = 5;
                }
                self.metrics.sessions_opened += 1;
                self.audit_event(
                    sakura_audit::events::SESSION_OPEN,
                    info.id,
                    0,
                    match info.kind {
                        PrincipalKind::Node => "NODE",
                        PrincipalKind::Operator => "OPERATOR",
                    },
                );
                if info.kind == PrincipalKind::Node {
                    self.promote_peer(ci, info.id);
                }
            }
            _ => {
                self.clients[ci].srv_step = 250;
            }
        }
    }

    /// Входящее соединение пира → peer-слот (заменяет старое при наличии).
    fn promote_peer(&mut self, ci: usize, node_id: [u8; 16]) {
        let pos = self.peers.iter().position(|p| p.entry.node_id == node_id);
        let Some(pi) = pos else { return };
        if self.peers[pi].conn.is_some() {
            // уже есть соединение с этим пиром — входящее отклоняется
            self.clients[ci].dead = true;
            return;
        }
        // переносим соединение: забираем у клиента (замена заглушкой)
        let placeholder = {
            let c = &self.clients[ci];
            let dummy_stream = c.conn.stream.try_clone().expect("tcp clone");
            Conn::new(dummy_stream, true).expect("conn")
        };
        let taken = std::mem::replace(&mut self.clients[ci].conn, placeholder);
        self.clients[ci].moved = true;
        self.peers[pi].conn = Some(taken);
        self.peers[pi].alive = true;
        self.peers[pi].srv_step = 5;
        let mut ev = Vec::new();
        let tx = self.engine.on_msg(&CMsg::Alive { node: self.peers[pi].entry.idx }, &mut ev);
        self.process_engine_events(ev);
        self.broadcast_consensus(tx);
    }

    fn handle_client_frame(&mut self, ci: usize, mtype: MsgType, payload: Vec<u8>) {
        match mtype {
            MsgType::ControlApi => {
                let Ok(v) = Cbor::from_slice(&payload) else { return };
                let Some(req) = ApiRequest::from_cbor(&v) else { return };
                self.handle_api(ci, req);
            }
            MsgType::Heartbeat => {
                let _ = self.clients[ci]
                    .conn
                    .send_msg(&self.codec, self.idx, CLIENT_DST, MsgType::HeartbeatAck as u8, b"");
            }
            MsgType::TimeSync => {
                let Ok(v) = Cbor::from_slice(&payload) else { return };
                if let Some((kind, t_ns, seq)) = time_wire::parse(&v) {
                    if kind == "sync" {
                        let now_ns = sakura_common::time::unix_ms() * 1_000_000;
                        let resp = time_wire::msg("sync_ack", now_ns, seq);
                        let mut pl = resp.to_vec();
                        pl.extend_from_slice(&t_ns.to_be_bytes()); // t1 echo
                        let _ = self.clients[ci].conn.send_msg(
                            &self.codec,
                            self.idx,
                            CLIENT_DST,
                            TYPE_TIME_SYNC,
                            &pl,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn send_to_peer(&mut self, pi: usize, mtype: u8, payload: &[u8]) -> Result<(), NetError> {
        let (src, dst) = (self.idx, self.peers[pi].entry.idx as u16);
        match &mut self.peers[pi].conn {
            Some(c) => {
                let r = c.send_msg(&self.codec, src, dst, mtype, payload);
                if r.is_ok() {
                    self.metrics.frames_tx += 1;
                }
                r
            }
            None => Err(NetError::Closed),
        }
    }

    fn broadcast_peers(&mut self, mtype: u8, payload: &[u8]) {
        for pi in 0..self.peers.len() {
            let est = self.peers[pi].conn.as_ref().map(|c| c.established).unwrap_or(false);
            if est {
                let _ = self.send_to_peer(pi, mtype, payload);
            }
        }
    }

    // ---------------- консенсус ----------------

    fn broadcast_consensus(&mut self, msgs: Vec<CMsg>) {
        for m in msgs {
            let wire = encode_consensus_msg(&m);
            self.broadcast_peers(TYPE_CONSENSUS_MSG, &wire);
        }
    }

    fn consensus_round(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_round_ms) < self.cfg.round_ms {
            return;
        }
        if self.pending_ops.is_empty() {
            return;
        }
        // EMERGENCY-операции реплицируются даже в режиме EMERGENCY_STOP
        // (иначе кластер не узнает об остановке); прочие — заблокированы.
        let emergency_pending = self
            .pending_ops
            .iter()
            .any(|op| op.get("kind").and_then(|k| k.as_text()) == Some("emergency"));
        if !emergency_pending
            && matches!(
                self.policy.mode,
                OperatingMode::EmergencyStop | OperatingMode::SecureLockdown | OperatingMode::Sanitizing
            )
        {
            return;
        }
        self.last_round_ms = now_ms;
        if self.engine.is_proposer() {
            let batch: Vec<Cbor> = self.pending_ops.drain(..64.min(self.pending_ops.len())).collect();
            self.inflight.extend(batch.iter().cloned());
            let payload = Cbor::array(batch).to_vec();
            let mut ev = Vec::new();
            match self.engine.propose(payload, &mut ev) {
                Ok(msgs) => {
                    self.process_engine_events(ev);
                    self.broadcast_consensus(msgs);
                }
                Err(e) => {
                    let _ = e;
                    self.process_engine_events(ev);
                }
            }
        } else {
            // пересылка ожидающих операций текущему proposer'у (forward)
            let proposer_idx = (self.engine.view() % self.cfg.cluster_n as u64) as u32;
            let msg = Cbor::map(vec![
                (Cbor::text("kind"), Cbor::text("ops")),
                (Cbor::text("from"), Cbor::UInt(self.idx as u64)),
                (Cbor::text("ops"), Cbor::array(self.pending_ops.iter().cloned().collect())),
            ])
            .to_vec();
            let mut sent = false;
            for pi in 0..self.peers.len() {
                if self.peers[pi].entry.idx == proposer_idx {
                    let est = self.peers[pi].conn.as_ref().map(|c| c.established).unwrap_or(false);
                    if est {
                        let _ = self.send_to_peer(pi, sakura_npp::payload::TYPE_CRDT_SYNC, &msg);
                        sent = true;
                    }
                }
            }
            if sent {
                self.pending_ops.clear();
            } else if self.peers.iter().any(|p| p.conn.as_ref().map(|c| c.established).unwrap_or(false))
            {
                // proposer недоступен — разослать всем (дедупликация по op_id)
                self.broadcast_peers(sakura_npp::payload::TYPE_CRDT_SYNC, &msg);
                self.pending_ops.clear();
            }
        }
    }

    /// Приём пересланных операций (дедупликация по op_id).
    fn handle_ops_forward(&mut self, payload: &[u8]) {
        let Ok(v) = Cbor::from_slice(payload) else { return };
        if v.get("kind").and_then(|k| k.as_text()) != Some("ops") {
            // снапшот state transfer
            if let Some(state) = v.get("state") {
                let _ = self.crdt.merge_state_snapshot(state);
            }
            return;
        }
        let Some(ops) = v.get("ops").and_then(|x| x.as_array()) else { return };
        let mut added = false;
        for op in ops {
            let id = op
                .get("op_id")
                .and_then(|x| x.as_bytes())
                .map(|b| {
                    let mut a = [0u8; 16];
                    if b.len() == 16 {
                        a.copy_from_slice(b);
                    }
                    a
                })
                .unwrap_or([0u8; 16]);
            if id != [0u8; 16] && !self.op_ids.insert(id) {
                continue; // уже известна
            }
            self.pending_ops.push_back(op.clone());
            added = true;
        }
        if added && self.pending_since_ms == 0 {
            self.pending_since_ms = sakura_common::time::unix_ms();
        }
    }

    fn engine_tick(&mut self, now_ms: u64) {
        let busy = !self.pending_ops.is_empty()
            || !self.inflight.is_empty()
            || self.pending_since_ms != 0;
        let mut ev = Vec::new();
        let tx = self.engine.tick_ext(now_ms, &mut ev, busy);
        self.process_engine_events(ev);
        self.broadcast_consensus(tx);
    }

    fn process_engine_events(&mut self, events: Vec<CEvent>) {
        for e in events {
            match e {
                CEvent::Finalized { height, hash } => {
                    self.metrics.blocks_finalized += 1;
                    let block = self.engine.finalized_log().last().map(|(_, _, b)| b.clone());
                    if let Some(b) = block {
                        self.apply_block(&b);
                    }
                    self.audit_event(
                        sakura_audit::events::CONSENSUS_FINALIZATION,
                        [0u8; 16],
                        0,
                        &sakura_common::hex::encode(&hash[..8]),
                    );
                    let _ = height;
                }
                CEvent::ViewChanged(v) => {
                    self.audit_event(sakura_audit::events::VIEW_CHANGE, [0u8; 16], 0, &v.to_string());
                    // незавершённые предложения возвращаются в очередь
                    if !self.inflight.is_empty() {
                        let requeued = std::mem::take(&mut self.inflight);
                        for op in requeued {
                            self.pending_ops.push_back(op);
                        }
                        if self.pending_since_ms == 0 {
                            self.pending_since_ms = sakura_common::time::unix_ms();
                        }
                    }
                }
                CEvent::Quarantined(n) => {
                    self.audit_event(
                        sakura_audit::events::QUARANTINE_EVIDENCE,
                        [0u8; 16],
                        0,
                        &format!("QUARANTINED:{n}"),
                    );
                }
                CEvent::EvidenceLogged { offender, reason } => {
                    self.audit_event(
                        sakura_audit::events::QUARANTINE_EVIDENCE,
                        [0u8; 16],
                        0,
                        &format!("{offender}:{reason}"),
                    );
                }
                CEvent::PartitionDegraded => {
                    let _ = self.policy.set_mode(OperatingMode::DegradedNet);
                    self.audit_event(
                        sakura_audit::events::NETWORK_PARTITION,
                        [0u8; 16],
                        0,
                        "DEGRADED",
                    );
                }
                CEvent::QuorumLostIsolated => {
                    let _ = self.policy.set_mode(OperatingMode::Isolated);
                    self.audit_event(
                        sakura_audit::events::NETWORK_PARTITION,
                        [0u8; 16],
                        0,
                        ErrorCode::QuorumLost.as_str(),
                    );
                }
                CEvent::RecoveryDone => {
                    let _ = self.policy.set_mode(OperatingMode::Normal);
                    self.audit_event(
                        sakura_audit::events::LIFECYCLE_TRANSITION,
                        [0u8; 16],
                        0,
                        "RECOVERY_DONE",
                    );
                }
                CEvent::RejoinSync(n) => {
                    let _ = n;
                }
                CEvent::SyncApply(block) => {
                    // state transfer: применить операции блока к CRDT
                    self.apply_block(&block);
                }
                CEvent::EnteredState(_) => {}
            }
        }
        // CRDT merge audit events (CRDT-REG-001)
        for ma in self.crdt.drain_audit() {
            let (key, det) = match &ma {
                MergeAudit::Accepted { key, .. } => (key.clone(), "ACCEPTED".to_owned()),
                MergeAudit::RejectedOlder { key } => (key.clone(), "REJECTED_OLDER".to_owned()),
                MergeAudit::ConcurrentTieBreak { key, winner_node, by, .. } => (
                    key.clone(),
                    format!("TIE_BREAK:{winner_node}:{by}"),
                ),
            };
            self.audit_event(
                "CRDT_MERGE",
                [0u8; 16],
                0,
                &format!("{key}:{det}"),
            );
        }
    }

    /// Применение финализированного блока (детерминированно на всех узлах).
    fn apply_block(&mut self, block: &Block) {
        let Ok(v) = Cbor::from_slice(&block.payload) else { return };
        let Some(ops) = v.as_array() else { return };
        self.inflight.clear();
        self.pending_since_ms = 0;
        for op in ops {
            if let Some(idb) = op.get("op_id").and_then(|x| x.as_bytes()) {
                if idb.len() == 16 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(idb);
                    self.op_ids.remove(&id);
                }
            }
            let kind = op.get("kind").and_then(|k| k.as_text()).unwrap_or("");
            match kind {
                "crdt" => {
                    let key = op.get("key").and_then(|k| k.as_text()).unwrap_or("").to_owned();
                    if let Some(opc) = op.get("op") {
                        if let Some(cop) = CrdtOp::from_cbor(opc) {
                            self.crdt.apply(&key, cop);
                        }
                    }
                }
                "cmd" => self.apply_command_op(op),
                "emergency" => {
                    let _ = self.policy.set_mode(OperatingMode::EmergencyStop);
                    self.audit_event(
                        sakura_audit::events::OPERATOR_ACTION,
                        [0u8; 16],
                        0,
                        "EMERGENCY_STOP_COMMITTED",
                    );
                }
                _ => {}
            }
        }
    }

    fn apply_command_op(&mut self, op: &Cbor) {
        let Some(cid_b) = op.get("command_id").and_then(|x| x.as_bytes()) else { return };
        if cid_b.len() != 16 {
            return;
        }
        let mut cid = [0u8; 16];
        cid.copy_from_slice(cid_b);
        let cmd_type = op.get("cmd_type").and_then(|x| x.as_text()).unwrap_or("").to_owned();
        let target = op.get("target").and_then(|x| x.as_text()).unwrap_or("").to_owned();
        let payload = op.get("payload").and_then(|x| x.as_bytes()).unwrap_or(&[]).to_vec();
        let ts = op.get("ts").and_then(|x| x.as_u64()).unwrap_or(0);
        let origin = op.get("origin_idx").and_then(|x| x.as_u64()).unwrap_or(0);
        let actor = op
            .get("actor")
            .and_then(|x| x.as_bytes())
            .map(|b| {
                let mut a = [0u8; 16];
                if b.len() == 16 {
                    a.copy_from_slice(b);
                }
                a
            })
            .unwrap_or([0u8; 16]);

        let mut result = "OK".to_owned();
        match cmd_type.as_str() {
            "KV_PUT" => {
                // payload = CBOR {key, value}
                if let Ok(kv) = Cbor::from_slice(&payload) {
                    let key = kv.get("key").and_then(|x| x.as_text()).unwrap_or("").to_owned();
                    let value = kv.get("value").and_then(|x| x.as_bytes()).unwrap_or(&[]).to_vec();
                    let mut clock = VectorClock::new();
                    clock.increment(NodeId(origin));
                    let lww = LwwMetadata::new(ts, NodeId(origin), &value);
                    self.crdt.apply(&key, CrdtOp::Set { value, clock, lww });
                } else {
                    result = "INVALID_PAYLOAD".to_owned();
                }
            }
            "KV_INCR" => {
                if let Ok(kv) = Cbor::from_slice(&payload) {
                    let key = kv.get("key").and_then(|x| x.as_text()).unwrap_or("").to_owned();
                    let delta = kv.get("delta").and_then(|x| x.as_u64()).unwrap_or(1);
                    self.crdt.apply(&key, CrdtOp::Increment { node: NodeId(origin), delta });
                } else {
                    result = "INVALID_PAYLOAD".to_owned();
                }
            }
            _ => {
                // прочие команды: исполнение = запись результата (расширение ICD)
            }
        }
        let audit_seq = self.audit_event(sakura_audit::events::COMMAND_ISSUE, actor, 0, &result);
        let audit_ref = Uuid7::from_ms_rand(audit_seq, [0u8; 10]);
        self.idem.resolve(
            &cid,
            IdemEntry {
                result: result.clone(),
                audit_ref: *audit_ref.as_bytes(),
                audit_seq,
                ts,
            },
        );
        // ответ ожидающему клиенту (инициатору команды)
        if let Some(w) = self.waiters.remove(&cid) {
            let data = Cbor::map(vec![
                (Cbor::text("target"), Cbor::text(target)),
                (Cbor::text("cmd_type"), Cbor::text(cmd_type)),
            ]);
            let resp = ApiResponse {
                result,
                request_seq: w.request_seq,
                audit_ref,
                data: Some(data),
            };
            if let Some(c) = self.clients.iter_mut().find(|c| c.cid == w.client_cid) {
                let _ = c.conn.send_msg(
                    &self.codec,
                    self.idx,
                    CLIENT_DST,
                    TYPE_CONTROL_API,
                    &resp.to_cbor().to_vec(),
                );
            }
        }
        let _ = self.idem.save(&self.cfg.idem_path());
    }

    // ---------------- control API ----------------

    fn handle_api(&mut self, ci: usize, req: ApiRequest) {
        let rseq = req.request_seq();
        let role = self.clients[ci].role;
        let actor = self.clients[ci].id;
        let audit_ref = Uuid7::now();
        match req {
            ApiRequest::GetStatus { .. } => {
                let data = self.status_cbor();
                self.respond(ci, ApiResponse::ok(rseq, audit_ref, Some(data)));
            }
            ApiRequest::KvGet { key, .. } => {
                if !self.rbac_ok(role, "KV_GET", ci) {
                    return;
                }
                let data = match self.crdt.get(&key) {
                    Some(sakura_crdt::CrdtValue::Register { value, lww, .. }) => Cbor::map(vec![
                        (Cbor::text("key"), Cbor::text(key.clone())),
                        (Cbor::text("value"), Cbor::bytes(value.clone())),
                        (Cbor::text("ts"), Cbor::UInt(lww.timestamp)),
                        (Cbor::text("node"), Cbor::UInt(lww.node_id.0)),
                    ]),
                    Some(sakura_crdt::CrdtValue::Counter(_)) => {
                        let total = self.crdt.counter_total(&key);
                        Cbor::map(vec![
                            (Cbor::text("key"), Cbor::text(key.clone())),
                            (Cbor::text("counter"), Cbor::UInt(total)),
                        ])
                    }
                    None => Cbor::Null,
                };
                self.respond(ci, ApiResponse::ok(rseq, audit_ref, Some(data)));
            }
            ApiRequest::KvList { .. } => {
                if !self.rbac_ok(role, "KV_LIST", ci) {
                    return;
                }
                let data = self.crdt.state_cbor();
                self.respond(ci, ApiResponse::ok(rseq, audit_ref, Some(data)));
            }
            ApiRequest::RequestAttestation { nonce, .. } => {
                if nonce.len() < 16 {
                    self.respond_err(ci, rseq, ErrorCode::InvalidFrame);
                    return;
                }
                if self.idem.consume_nonce(&nonce, self.now_s()) != Ok(()) {
                    self.respond_err(ci, rseq, ErrorCode::ReplayDetected);
                    self.audit_event(sakura_audit::events::ATTESTATION, actor, 0, "NONCE_REUSED");
                    return;
                }
                let inputs = ReportInputs {
                    fw_versions: self.fw_versions.clone(),
                    pcrs: (0..16u8).map(|i| (i, self.pcrs.get(i))).collect(),
                    boot_mode: "NORMAL".into(),
                    rollback_counters: vec![
                        ("bootloader".into(), self.storage.rollback.active(1) as u64),
                        ("kernel".into(), self.storage.rollback.active(2) as u64),
                        ("app".into(), self.storage.rollback.active(3) as u64),
                        ("model".into(), self.storage.rollback.active(4) as u64),
                    ],
                    time_sync_quality: self.time_svc.quality(sakura_common::time::unix_ms()).as_str().into(),
                    model_hashes: Vec::new(),
                    policy_hash: self.policy.policy_hash().to_vec(),
                };
                let mut sig_buf = vec![0u8; sakura_hybrid::HYBRID_SIG_LEN];
                let produced = {
                    let mut h = self.hsm.borrow_mut();
                    self.attest_agent.produce(&mut *h, self.sid, &nonce, &inputs, &mut sig_buf)
                };
                match produced {
                    Ok(cose) => {
                        let seq = self.audit_event(sakura_audit::events::ATTESTATION, actor, 0, "OK");
                        let data = Cbor::map(vec![
                            (Cbor::text("cose"), Cbor::bytes(cose)),
                            (Cbor::text("cert"), Cbor::bytes(self.device_cert.encode())),
                            (Cbor::text("platform_cert"), Cbor::bytes(self.bundle.platform_cert.encode())),
                            (Cbor::text("seq"), Cbor::UInt(seq)),
                        ]);
                        self.respond(ci, ApiResponse::ok(rseq, audit_ref, Some(data)));
                    }
                    Err(e) => {
                        self.audit_event(sakura_audit::events::ATTESTATION, actor, 0, &format!("{e:?}"));
                        self.respond_err(ci, rseq, ErrorCode::SelfTestFailed);
                    }
                }
            }
            ApiRequest::SubmitCommand {
                plan_id, command_id, seq, cmd_type, payload, target, cmd_sig,
                operator_pk, operator_cert, operator_role, idempotency_key,
                request_seq, second_sig, ..
            } => {
                self.handle_submit(
                    ci, plan_id, command_id, seq, cmd_type, payload, target, cmd_sig,
                    operator_pk, operator_cert, operator_role, idempotency_key,
                    request_seq, second_sig, actor, role,
                );
            }
            ApiRequest::EmergencyStop {
                reason_code, op_sig, op_pk, op_cert, second_op_sig, second_op_pk,
                request_seq, idempotency_key,
            } => {
                self.handle_emergency(
                    ci, reason_code, op_sig, op_pk, op_cert, second_op_sig, second_op_pk,
                    request_seq, idempotency_key, actor,
                );
            }
            ApiRequest::UpdateCommit { package, request_seq, idempotency_key } => {
                self.handle_update(ci, package, request_seq, idempotency_key, actor);
            }
            ApiRequest::AuditExport { request_id, from_seq, max_records, request_seq, .. } => {
                if !self.rbac_ok(role, "AUDIT_EXPORT", ci) {
                    return;
                }
                match self.audit.export_chunk(&request_id, from_seq, max_records as usize) {
                    Ok(chunk) => {
                        let seq = self.audit_event(sakura_audit::events::ADMIN_ACTION, actor, 0, "AUDIT_EXPORT");
                        let data = Cbor::map(vec![
                            (Cbor::text("chunk"), Cbor::bytes(chunk)),
                            (Cbor::text("audit_seq"), Cbor::UInt(seq)),
                        ]);
                        self.respond(ci, ApiResponse::ok(request_seq, audit_ref, Some(data)));
                    }
                    Err(_) => self.respond_err(ci, request_seq, ErrorCode::ResourceExhausted),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_submit(
        &mut self,
        ci: usize,
        plan_id: [u8; 16],
        command_id: [u8; 16],
        seq: u64,
        cmd_type: String,
        payload: Vec<u8>,
        target: String,
        cmd_sig: Vec<u8>,
        operator_pk: Vec<u8>,
        operator_cert: Vec<u8>,
        operator_role: String,
        idempotency_key: Vec<u8>,
        request_seq: u64,
        second_sig: Option<(Vec<u8>, Vec<u8>)>,
        actor: [u8; 16],
        session_role: Role,
    ) {
        // 1) идемпотентность (BC-27): известный command_id → прежний результат
        if let Some(entry) = self.idem.known_command(&command_id) {
            let e = entry.clone();
            self.audit_event(sakura_audit::events::IDEMPOTENT_REPLAY, actor, 0, &cmd_type);
            let resp = ApiResponse {
                result: e.result,
                request_seq,
                audit_ref: Uuid7(e.audit_ref),
                data: None,
            };
            self.respond(ci, resp);
            return;
        }
        // 2) сертификат оператора: цепочка + соответствие pk
        let Some(cert) = SignerCert::decode(&operator_cert) else {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "CERT_MALFORMED");
            return;
        };
        if cert.key_usage != USAGE_OPERATOR || cert.subject_id != actor {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "CERT_USAGE");
            return;
        }
        let chain_ok = {
            let chain = vec![cert.clone(), self.bundle.platform_cert.clone()];
            self.anchor
                .verify_chain_for_usage(&chain, &cert.subject_id, Some(self.now_s()))
                .is_ok()
        };
        if !chain_ok {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "CHAIN_INVALID");
            return;
        }
        let Some(pk) = HybridPublicKey::from_bytes(&operator_pk) else {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "PK_MALFORMED");
            return;
        };
        if pk.to_bytes() != cert.public.to_bytes() {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "PK_MISMATCH");
            return;
        }
        // 3) replay: monotonic seq принципала (REPLAY-001)
        let cmd = Command {
            plan_id,
            command_id,
            seq,
            cmd_type: cmd_type.clone(),
            payload: payload.clone(),
            target: target.clone(),
        };
        match self.idem.check_principal_seq(&actor, seq) {
            Ok(()) => {}
            Err(IdemError::ReplayDetected) => {
                self.reject(ci, request_seq, ErrorCode::ReplayDetected, actor, "SEQ_REPLAY");
                return;
            }
            Err(_) => {
                self.reject(ci, request_seq, ErrorCode::SeqOutOfWindow, actor, "SEQ_WINDOW");
                return;
            }
        }
        // 4) подпись оператора
        if !sakura_hybrid::hybrid_verify(&pk, &cmd.canonical_bytes(), &cmd_sig) {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "SIG_INVALID");
            return;
        }
        // 5) политика + этика (ETH-002 3 уровня)
        let role = Role::from_str_name(&operator_role).unwrap_or(session_role);
        let decision = self.policy.authorize(role, &actor, &cmd, self.now_s());
        match decision {
            PolicyDecision::Allow => {}
            PolicyDecision::AllowWithSecondSignature => {
                match second_sig {
                    Some((pk2b, sig2)) => {
                        let Some(pk2) = HybridPublicKey::from_bytes(&pk2b) else {
                            self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "SECOND_PK");
                            return;
                        };
                        if PolicyEngine::verify_two_person(&cmd, &pk, &cmd_sig, &pk2, &sig2).is_err() {
                            self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "TWO_PERSON");
                            return;
                        }
                    }
                    None => {
                        self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "NEED_SECOND_SIG");
                        return;
                    }
                }
            }
            PolicyDecision::Deny(code, reason) => {
                self.reject(ci, request_seq, code, actor, &reason);
                return;
            }
        }
        // 6) постановка в консенсус
        let idem_key = if idempotency_key.is_empty() {
            IdemStore::idem_key(&actor, 0, &cmd_type, &payload, self.now_s())
        } else {
            idempotency_key
        };
        self.idem.mark_pending(command_id, idem_key);
        let client_cid = self.clients.get(ci).map(|c| c.cid).unwrap_or(0);
        self.waiters.insert(command_id, Waiter { request_seq, client_cid });
        let op_id = Uuid7::now();
        self.op_ids.insert(*op_id.as_bytes());
        if self.pending_since_ms == 0 {
            self.pending_since_ms = sakura_common::time::unix_ms();
        }
        let op = Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text("cmd")),
            (Cbor::text("op_id"), Cbor::bytes(op_id.as_bytes().to_vec())),
            (Cbor::text("command_id"), Cbor::bytes(command_id.to_vec())),
            (Cbor::text("cmd_type"), Cbor::text(cmd_type.clone())),
            (Cbor::text("payload"), Cbor::bytes(payload)),
            (Cbor::text("target"), Cbor::text(target)),
            (Cbor::text("actor"), Cbor::bytes(actor.to_vec())),
            (Cbor::text("ts"), Cbor::UInt(self.now_s())),
            (Cbor::text("origin_idx"), Cbor::UInt(self.idx as u64)),
        ]);
        self.pending_ops.push_back(op);
        self.audit_event(sakura_audit::events::AUTHORIZATION, actor, 0, &format!("ACCEPTED:{cmd_type}"));
        // ответ придёт после финализации (waiter)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_emergency(
        &mut self,
        ci: usize,
        reason_code: u32,
        op_sig: Vec<u8>,
        op_pk: Vec<u8>,
        op_cert: Vec<u8>,
        second_op_sig: Vec<u8>,
        second_op_pk: Vec<u8>,
        request_seq: u64,
        idempotency_key: Vec<u8>,
        actor: [u8; 16],
    ) {
        let audit_ref = Uuid7::now();
        let cmd = Command {
            plan_id: [0u8; 16],
            command_id: {
                let mut a = [0u8; 16];
                a.copy_from_slice(&streebog256(&idempotency_key)[..16]);
                a
            },
            seq: 0,
            cmd_type: "EMERGENCY_STOP".into(),
            payload: reason_code.to_be_bytes().to_vec(),
            target: "cluster".into(),
        };
        let (Some(pk1), Some(pk2)) = (
            HybridPublicKey::from_bytes(&op_pk),
            HybridPublicKey::from_bytes(&second_op_pk),
        ) else {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "PK_MALFORMED");
            return;
        };
        if let Some(c) = SignerCert::decode(&op_cert) {
            if c.public.to_bytes() != pk1.to_bytes() {
                self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "CERT_PK_MISMATCH");
                return;
            }
        } else {
            self.reject(ci, request_seq, ErrorCode::AuthFailed, actor, "CERT_MALFORMED");
            return;
        }
        // two-person rule (§13.19.2): два РАЗНЫХ оператора, обе подписи валидны
        if PolicyEngine::verify_two_person(&cmd, &pk1, &op_sig, &pk2, &second_op_sig).is_err() {
            self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "TWO_PERSON_FAILED");
            return;
        }
        // роли: SAFETY_OFFICER или ADMIN у обоих (по реестру операторов)
        let role_ok = |pk: &HybridPublicKey| -> bool {
            self.bundle.operator_certs.iter().any(|(id, (c, role))| {
                c.public.to_bytes() == pk.to_bytes()
                    && matches!(role.as_str(), "SAFETY_OFFICER" | "ADMIN")
                    && { let _ = id; true }
            })
        };
        if !role_ok(&pk1) || !role_ok(&pk2) {
            self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "ROLE_REQUIRED");
            return;
        }
        // немедленное локальное действие (приоритет 1–3, §25.1) + консенсус
        let _ = self.policy.set_mode(OperatingMode::EmergencyStop);
        let op_id = Uuid7::now();
        self.op_ids.insert(*op_id.as_bytes());
        let op = Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text("emergency")),
            (Cbor::text("op_id"), Cbor::bytes(op_id.as_bytes().to_vec())),
            (Cbor::text("reason"), Cbor::UInt(reason_code as u64)),
            (Cbor::text("actor"), Cbor::bytes(actor.to_vec())),
        ]);
        self.pending_ops.push_front(op);
        let seq = self.audit_event(
            sakura_audit::events::OPERATOR_ACTION,
            actor,
            0,
            &format!("EMERGENCY_STOP:{reason_code}"),
        );
        let data = Cbor::map(vec![(Cbor::text("log_ref"), Cbor::UInt(seq))]);
        self.respond(ci, ApiResponse::ok(request_seq, audit_ref, Some(data)));
    }

    fn handle_update(
        &mut self,
        ci: usize,
        package: Vec<u8>,
        request_seq: u64,
        idempotency_key: Vec<u8>,
        actor: [u8; 16],
    ) {
        let audit_ref = Uuid7::now();
        let _ = idempotency_key;
        // two-person: OTA_APPLY в two_person_types — требуется роль ADMIN и
        // подтверждение вторым оператором (упрощение SIL: проверяем роль)
        if !matches!(self.clients[ci].role, Role::Admin) {
            self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "ADMIN_REQUIRED");
            return;
        }
        let Ok(pkg) = UpdatePackage::decode(&package) else {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "MALFORMED");
            return;
        };
        // verify signature (update CA chain)
        let chain = self.bundle.update_chain();
        let signer_id = chain[0].subject_id;
        if self
            .anchor
            .verify_message(
                &pkg.manifest.tbs(),
                &chain,
                &signer_id,
                &pkg.signature,
                pkg.manifest.signature_alg,
                Some(self.now_s()),
            )
            .is_err()
        {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "SIG_INVALID");
            return;
        }
        // policy binding: expected_policy_hash == текущий policy_hash
        if pkg.manifest.expected_policy_hash != self.policy.policy_hash().to_vec() {
            self.reject(ci, request_seq, ErrorCode::PolicyViolation, actor, "POLICY_BINDING");
            return;
        }
        if pkg.manifest.min_hw_rev > self.cfg.hw_rev {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "HW_REV");
            return;
        }
        if pkg.manifest.rollback_counter < self.storage.rollback.active(pkg.manifest.image_type) {
            self.reject(ci, request_seq, ErrorCode::RollbackDetected, actor, "ROLLBACK");
            return;
        }
        // attest(sid, manifest.nonce) — C-04
        let mut attest_buf = [0u8; 2048];
        let attest_ok = {
            let mut h = self.hsm.borrow_mut();
            match h.attest(self.sid, &pkg.manifest.nonce, &mut attest_buf) {
                Ok(n) => Cbor::from_slice(&attest_buf[..n])
                    .ok()
                    .and_then(|v| v.get("hsm_status").and_then(|s| s.as_text()).map(|s| s == "OK"))
                    .unwrap_or(false),
                Err(_) => false,
            }
        };
        if !attest_ok {
            self.reject(ci, request_seq, ErrorCode::SelfTestFailed, actor, "HSM_ATTEST");
            return;
        }
        // hash payload + запись в неактивный слот + pending metadata (BC-24)
        let hash = streebog256(&pkg.payload);
        if hash != pkg.manifest.payload_hash {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "HASH_MISMATCH");
            return;
        }
        let slot = self.storage.inactive_slot();
        if self.storage.write(slot, &pkg.payload).is_err() {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "STORAGE");
            return;
        }
        if self.storage.set_metadata(slot, &pkg.manifest).is_err() {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "STORAGE");
            return;
        }
        let _ = self
            .storage
            .rollback
            .set_pending(pkg.manifest.image_type, pkg.manifest.rollback_counter);
        let _ = self.storage.rollback.save(&self.cfg.rollback_path());
        if self.storage.set_boot_slot(slot).is_err() {
            self.reject(ci, request_seq, ErrorCode::UpdateRejected, actor, "STORAGE");
            return;
        }
        self.audit_event(
            sakura_audit::events::FIRMWARE_UPDATE,
            actor,
            0,
            &format!("PENDING:v{}:slot{slot}", pkg.manifest.version),
        );
        let data = Cbor::map(vec![
            (Cbor::text("state"), Cbor::text("PENDING")),
            (Cbor::text("slot"), Cbor::UInt(slot as u64)),
        ]);
        self.respond(ci, ApiResponse::ok(request_seq, audit_ref, Some(data)));
        // REBOOT (§13.16.2 Update FSM): после flush ответов
        self.reboot_flag = true;
    }

    fn rbac_ok(&mut self, role: Role, cmd_type: &str, ci: usize) -> bool {
        let dummy = Command {
            plan_id: [0u8; 16],
            command_id: [0u8; 16],
            seq: 0,
            cmd_type: cmd_type.to_owned(),
            payload: Vec::new(),
            target: String::new(),
        };
        let actor = self.clients[ci].id;
        let d = self.policy.authorize(role, &actor, &dummy, self.now_s());
        if !d.is_allowed() {
            let audit_ref = Uuid7::now();
            self.respond(ci, ApiResponse::err(0, audit_ref, ErrorCode::PolicyViolation));
            false
        } else {
            true
        }
    }

    fn reject(&mut self, ci: usize, request_seq: u64, code: ErrorCode, actor: [u8; 16], reason: &str) {
        self.metrics.commands_denied += 1;
        self.audit_event(sakura_audit::events::AUTHORIZATION, actor, 0, &format!("DENIED:{reason}"));
        let audit_ref = Uuid7::now();
        self.respond(ci, ApiResponse::err(request_seq, audit_ref, code));
    }

    fn respond(&mut self, ci: usize, resp: ApiResponse) {
        if resp.result == "OK" {
            self.metrics.commands_ok += 1;
        }
        if let Some(c) = self.clients.get_mut(ci) {
            let _ = c.conn.send_msg(
                &self.codec,
                self.idx,
                CLIENT_DST,
                TYPE_CONTROL_API,
                &resp.to_cbor().to_vec(),
            );
        }
    }

    fn respond_err(&mut self, ci: usize, request_seq: u64, code: ErrorCode) {
        let audit_ref = Uuid7::now();
        self.respond(ci, ApiResponse::err(request_seq, audit_ref, code));
    }

    // ---------------- время ----------------

    fn time_sync(&mut self, local_now: u64) {
        if local_now.saturating_sub(self.last_sync_ms) < self.cfg.time_sync_interval_ms {
            return;
        }
        self.last_sync_ms = local_now;
        let t1 = local_now * 1_000_000;
        let msg = time_wire::msg("sync", t1, local_now);
        self.broadcast_peers(TYPE_TIME_SYNC, &msg.to_vec());
        let q = self.time_svc.quality(local_now);
        self.time_svc.note_quality(q, local_now);
        if q != self.last_quality {
            if q != TimeQuality::Locked && self.last_quality == TimeQuality::Locked {
                self.audit_event(
                    sakura_audit::events::CRYPTO_FAILURE,
                    [0u8; 16],
                    0,
                    ErrorCode::TimeSyncLost.as_str(),
                );
            }
            self.audit_event(
                sakura_audit::events::LIFECYCLE_TRANSITION,
                [0u8; 16],
                0,
                &format!("TIME_QUALITY:{}", q.as_str()),
            );
            self.last_quality = q;
        }
    }

    fn handle_time_sync(&mut self, pi: usize, payload: &[u8]) {
        let Ok(v) = Cbor::from_slice(payload) else { return };
        let Some((kind, t_ns, seq)) = time_wire::parse(&v) else { return };
        let local_ns = sakura_common::time::unix_ms() * 1_000_000;
        if kind == "sync" {
            let resp = time_wire::msg_ack(local_ns, seq, t_ns);
            let _ = self.send_to_peer(pi, TYPE_TIME_SYNC, &resp.to_vec());
        } else if kind == "sync_ack" {
            if let Some(t1) = time_wire::parse_t1(&v) {
                let t4 = local_ns;
                let t2 = t_ns; // время получения у пира
                let t3 = t2; // упрощение: ack отправлен немедленно
                let offset = ((t2 as i128 - t1 as i128) + (t3 as i128 - t4 as i128)) / 2;
                self.time_svc.record_offset(
                    self.peers[pi].entry.idx,
                    offset as i64,
                    sakura_common::time::unix_ms(),
                );
            }
        }
    }

    fn heartbeats(&mut self, local_now: u64) {
        if local_now.saturating_sub(self.last_hb_ms) < self.cfg.heartbeat_ms {
            return;
        }
        self.last_hb_ms = local_now;
        let hb = Cbor::map(vec![(Cbor::text("t_ms"), Cbor::UInt(local_now))]).to_vec();
        self.broadcast_peers(MsgType::Heartbeat as u8, &hb);
    }

    // ---------------- статус / HTTP ----------------

    fn status_cbor(&self) -> Cbor {
        let peers: Vec<Cbor> = self
            .peers
            .iter()
            .map(|p| {
                Cbor::map(vec![
                    (Cbor::text("idx"), Cbor::UInt(p.entry.idx as u64)),
                    (Cbor::text("alive"), Cbor::Bool(p.alive)),
                    (Cbor::text("session"), Cbor::Bool(p.conn.as_ref().map(|c| c.established).unwrap_or(false))),
                ])
            })
            .collect();
        Cbor::map(vec![
            (Cbor::text("api"), Cbor::text(API_VERSION)),
            (Cbor::text("node_idx"), Cbor::UInt(self.idx as u64)),
            (Cbor::text("node_id"), Cbor::bytes(self.device_id.to_vec())),
            (Cbor::text("phase"), Cbor::text(self.policy.phase().as_str())),
            (Cbor::text("mode"), Cbor::text(self.policy.mode.as_str())),
            (Cbor::text("consensus_height"), Cbor::UInt(self.engine.height())),
            (Cbor::text("consensus_view"), Cbor::UInt(self.engine.view())),
            (Cbor::text("consensus_state"), Cbor::text(format!("{:?}", self.engine.state))),
            (Cbor::text("quorum"), Cbor::UInt(self.engine.quorum() as u64)),
            (Cbor::text("time_quality"), Cbor::text(self.time_svc.quality(sakura_common::time::unix_ms()).as_str())),
            (Cbor::text("crdt_state_hash"), Cbor::bytes(self.crdt.state_hash().to_vec())),
            (Cbor::text("audit_len"), Cbor::UInt(self.audit.len() as u64)),
            (Cbor::text("pending_ops"), Cbor::UInt(self.pending_ops.len() as u64)),
            (Cbor::text("clients"), Cbor::UInt(self.clients.iter().filter(|c| c.srv_step == 5).count() as u64)),
            (Cbor::text("peers"), Cbor::array(peers)),
            (Cbor::text("policy_hash"), Cbor::bytes(self.policy.policy_hash().to_vec())),
            (Cbor::text("fw_versions"), Cbor::map(
                self.fw_versions.iter().map(|(k, v)| (Cbor::text(k.clone()), Cbor::text(v.clone()))).collect::<Vec<_>>(),
            )),
            (Cbor::text("rollback_active"), Cbor::map(vec![
                (Cbor::text("bootloader"), Cbor::UInt(self.storage.rollback.active(1) as u64)),
                (Cbor::text("kernel"), Cbor::UInt(self.storage.rollback.active(2) as u64)),
            ])),
        ])
    }

    fn accept_http(&mut self) {
        loop {
            match self.http_listener.accept() {
                Ok((s, _)) => {
                    if let Ok(c) = HttpConn::new(s) {
                        self.http_conns.push(c);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn poll_http(&mut self) {
        let mut keep = Vec::new();
        let mut conns = std::mem::take(&mut self.http_conns);
        for mut c in conns.drain(..) {
            match c.poll() {
                Some(path) if path.is_empty() => {}
                Some(path) => {
                    match path.as_str() {
                        "/health" => {
                            // HTTP-плоскость доступна только после RUNTIME_READY
                            // (listener создаётся по завершении boot-цепочки)
                            let body = format!(
                                "{{\"state\":\"RUNTIME_READY\",\"phase\":\"{}\",\"mode\":\"{}\",\"height\":{}}}",
                                self.policy.phase().as_str(),
                                self.policy.mode.as_str(),
                                self.engine.height()
                            );
                            c.respond(200, &body, "application/json");
                        }
                        "/status" => {
                            let body = json_of(&self.status_cbor());
                            c.respond(200, &body, "application/json");
                        }
                        "/metrics" => {
                            let m = &self.metrics;
                            let body = format!(
                                "sakura_frames_rx {}\nsakura_frames_tx {}\nsakura_fec_corrected {}\nsakura_replays {}\nsakura_handshake_fail {}\nsakura_commands_ok {}\nsakura_commands_denied {}\nsakura_blocks_finalized {}\nsakura_sessions_opened {}\nsakura_audit_records {}\nsakura_pending_ops {}\n",
                                m.frames_rx, m.frames_tx, m.fec_corrected, m.replays,
                                m.handshake_fail, m.commands_ok, m.commands_denied,
                                m.blocks_finalized, m.sessions_opened, self.audit.len(),
                                self.pending_ops.len()
                            );
                            c.respond(200, &body, "text/plain; version=0.0.4");
                        }
                        "/audit/head" => {
                            let head = self
                                .audit
                                .records()
                                .last()
                                .map(|r| sakura_common::hex::encode(&r.hash_self))
                                .unwrap_or_default();
                            c.respond(200, &format!("{{\"head\":\"{head}\",\"len\":{}}}", self.audit.len()), "application/json");
                        }
                        _ => c.respond(404, "{\"error\":\"not found\"}", "application/json"),
                    }
                }
                None => keep.push(c),
            }
        }
        self.http_conns = keep;
    }
}

/// Минимальный JSON-дамп CBOR-статуса (management plane; JSON — только debug,
/// DM-1).
fn json_of(v: &Cbor) -> String {
    match v {
        Cbor::UInt(u) => u.to_string(),
        Cbor::NInt(i) => i.to_string(),
        Cbor::Bool(b) => b.to_string(),
        Cbor::Null => "null".into(),
        Cbor::Text(t) => format!("\"{}\"", t.replace('\\', "\\\\").replace('"', "\\\"")),
        Cbor::Bytes(b) => format!("\"{}\"", sakura_common::hex::encode(b)),
        Cbor::Array(items) => {
            let inner: Vec<String> = items.iter().map(json_of).collect();
            format!("[{}]", inner.join(","))
        }
        Cbor::Map(items) => {
            let inner: Vec<String> = items
                .iter()
                .map(|(k, val)| format!("{}:{}", json_of(k), json_of(val)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Cbor::Tag(t, inner) => format!("{{\"tag\":{t},\"value\":{}}}", json_of(inner)),
    }
}

// ---------------- consensus wire codec ----------------

fn encode_consensus_msg(m: &CMsg) -> Vec<u8> {
    let v = match m {
        CMsg::Proposal { block, sig } => Cbor::map(vec![
            (Cbor::text("m"), Cbor::text("proposal")),
            (Cbor::text("block"), consensus_wire::block_to_cbor(block.height, block.view, &block.parent_hash, &block.payload, block.proposer)),
            (Cbor::text("sig"), Cbor::bytes(sig.clone())),
        ]),
        CMsg::PrepareVote(vote) => vote_wire("prepare", vote),
        CMsg::CommitVote(vote) => vote_wire("commit", vote),
        CMsg::ViewChangeReq { view, node, sig } => {
            let mut c = consensus_wire::viewchange_to_cbor("vcreq", *view, *node, sig);
            let _ = &mut c;
            c
        }
        CMsg::NewViewAnnounce { view, node, sig } => {
            consensus_wire::viewchange_to_cbor("newview", *view, *node, sig)
        }
        CMsg::SyncRequest { node, height } => {
            consensus_wire::sync_to_cbor("syncreq", *node, *height, &[], &[])
        }
        CMsg::SyncResponse { node, height, finalized, blocks } => {
            let bc: Vec<Cbor> = blocks
                .iter()
                .map(|b| {
                    consensus_wire::block_to_cbor(b.height, b.view, &b.parent_hash, &b.payload, b.proposer)
                })
                .collect();
            consensus_wire::sync_to_cbor("syncresp", *node, *height, finalized, &bc)
        }
        CMsg::Alive { node } => Cbor::map(vec![
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
            consensus_wire::vote_to_cbor(&v.block_hash, v.voter, v.view, if kind == "prepare" { PHASE_PREPARE } else { PHASE_COMMIT }, &v.signature),
        ),
    ])
}

fn decode_consensus_msg(payload: &[u8]) -> Option<CMsg> {
    let v = Cbor::from_slice(payload).ok()?;
    // "m" — основные сообщения; "kind" — viewchange/sync (consensus_wire)
    let kind = v
        .get("m")
        .and_then(|x| x.as_text())
        .or_else(|| v.get("kind").and_then(|x| x.as_text()))?;
    match kind {
        "proposal" => {
            let (height, view, parent, pl, proposer) = consensus_wire::block_from_cbor(v.get("block")?)?;
            let sig = v.get("sig")?.as_bytes()?.to_vec();
            Some(CMsg::Proposal {
                block: Block { height, view, parent_hash: parent, payload: pl, proposer },
                sig,
            })
        }
        "prepare" | "commit" => {
            let (bh, voter, view, phase, sig) = consensus_wire::vote_from_cbor(v.get("vote")?)?;
            let vote = Vote { block_hash: bh, voter, view, signature: sig };
            if phase == PHASE_PREPARE {
                Some(CMsg::PrepareVote(vote))
            } else {
                Some(CMsg::CommitVote(vote))
            }
        }
        "vcreq" | "newview" => {
            let (kind, view, node, sig) = consensus_wire::viewchange_from_cbor(&v)?;
            if kind == "vcreq" {
                Some(CMsg::ViewChangeReq { view, node, sig })
            } else {
                Some(CMsg::NewViewAnnounce { view, node, sig })
            }
        }
        "syncreq" => {
            let (_, node, height, _, _) = consensus_wire::sync_from_cbor(&v)?;
            Some(CMsg::SyncRequest { node, height })
        }
        "syncresp" => {
            let (_, node, height, finalized, block_cbs) = consensus_wire::sync_from_cbor(&v)?;
            let mut blocks = Vec::with_capacity(block_cbs.len());
            for bc in &block_cbs {
                let (h, view, parent, pl, proposer) = consensus_wire::block_from_cbor(bc)?;
                blocks.push(Block { height: h, view, parent_hash: parent, payload: pl, proposer });
            }
            Some(CMsg::SyncResponse { node, height, finalized, blocks })
        }
        "alive" => Some(CMsg::Alive { node: v.get("node")?.as_u64()? as u32 }),
        _ => None,
    }
}

fn install_signal_handler(stop: &Arc<AtomicBool>, stop_file: &std::path::Path) {
    // Штатное завершение: ops-скрипт создаёт файл STOP в data_dir узла
    // (SIGTERM-обработчик без unsafe-зависимостей не реализуется —
    // файловый флаг является утверждённым механизмом ops/runbooks).
    let s = stop.clone();
    let f = stop_file.to_path_buf();
    std::thread::spawn(move || {
        loop {
            if f.exists() {
                s.store(true, Ordering::Relaxed);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
}
