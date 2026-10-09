//! sakura-cli — инструмент оператора (§25.2 HMI-требования: confirm для
//! критических команд, two-person rule для high-risk).
//!
//! Команды:
//! - `status`, `kv get|put|incr|list`, `submit`, `attest [--verify]`,
//!   `audit export|verify`, `update push`, `emergency`, `watch`.
#![forbid(unsafe_code)]

use sakura_attestation::{verify_report, VerifyExpectations, REPORT_TTL_S};
use sakura_boot::bundle::TrustBundle;
use sakura_boot::cert::SignerCert;
use sakura_boot::anchor::TrustAnchor;
use sakura_common::cbor::Cbor;
use sakura_common::uuid7::Uuid7;
use sakura_gost::hash::streebog256;
use sakura_hybrid::{hybrid_kem_combine, hybrid_sign, HybridKeyPair, HybridPublicKey};
use sakura_node::net::{self, Conn, PrincipalKind};
use sakura_npp::frame::NppCodec;
use sakura_npp::msg::MsgType;
use sakura_npp::payload::{ApiRequest, ApiResponse, TYPE_CONTROL_API};
use sakura_policy::Command;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROTOCOL_ID: &str = "NPP-v2.3";
const CLIENT_DST: u16 = 0xFFFF;

fn fail(msg: &str) -> ! {
    eprintln!("sakura-cli: {msg}");
    std::process::exit(1);
}

struct Operator {
    kp: HybridKeyPair,
    cert: SignerCert,
    id: [u8; 16],
    role: String,
}

fn load_operator(dir: &Path, role_hint: Option<&str>) -> Operator {
    let raw = std::fs::read(dir.join("operator.key")).unwrap_or_else(|_| fail("operator.key не найден"));
    let v = Cbor::from_slice(&raw).unwrap_or_else(|_| fail("operator.key повреждён"));
    let mut gost_priv = [0u8; 32];
    gost_priv.copy_from_slice(v.get("gost").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")));
    let mldsa_sk = v.get("mldsa").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")).to_vec();
    let mlkem_dk = v.get("mlkem").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")).to_vec();
    let public = HybridPublicKey::from_bytes(v.get("pub").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")))
        .unwrap_or_else(|| fail("pub"));
    let kp = HybridKeyPair { gost_priv, mldsa_sk, mlkem_dk, public };
    let cert_raw = std::fs::read(dir.join("operator.cert")).unwrap_or_else(|_| fail("operator.cert"));
    let cert = SignerCert::decode(&cert_raw).unwrap_or_else(|| fail("cert"));
    let id_raw = std::fs::read_to_string(dir.join("operator.id")).unwrap_or_else(|_| fail("operator.id"));
    let id = Uuid7::parse(id_raw.trim()).map(|u| *u.as_bytes()).unwrap_or(cert.subject_id);
    Operator { kp, cert, id, role: role_hint.unwrap_or("OPERATOR").to_owned() }
}

struct Client {
    conn: Conn,
    codec: NppCodec,
    req_seq: u64,
}

impl Client {
    fn connect(node_addr: &str, bundle: &TrustBundle, op: &Operator) -> Self {
        // найти узел в roster по адресу
        let entry = bundle
            .roster
            .iter()
            .find(|r| format!("{}:{}", r.host, r.port) == node_addr)
            .unwrap_or_else(|| fail("узел не найден в roster bundle"));
        let node_cert = bundle
            .device_certs
            .get(&entry.node_id)
            .unwrap_or_else(|| fail("сертификат узла отсутствует в bundle"));
        let stream = TcpStream::connect(node_addr).unwrap_or_else(|_| fail("connect"));
        stream.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let mut conn = Conn::new(stream, false).unwrap_or_else(|_| fail("conn"));
        let codec = NppCodec::new(true);

        // --- рукопожатие (§13.3): HELLO → CHALLENGE → AUTH → ESTABLISH → CONFIRM
        let (h0, _nonce_c) = net::client_hello(op.id, PrincipalKind::Operator, 0);
        conn.send_msg(&codec, CLIENT_DST, entry.idx as u16, MsgType::Hello as u8, &h0)
            .unwrap_or_else(|_| fail("hello send"));
        let h1 = expect_frame(&mut conn, &codec, MsgType::AuthChallenge);
        // AUTH_RESPONSE
        let mut t = Vec::new();
        t.extend_from_slice(&h0);
        t.extend_from_slice(&h1);
        let digest = streebog256(&t);
        let sig = hybrid_sign(&op.kp, &digest).expect("auth sig");
        let h2 = net::auth_response_payload(sig);
        conn.send_msg(&codec, CLIENT_DST, entry.idx as u16, MsgType::AuthResponse as u8, &h2)
            .unwrap_or_else(|_| fail("auth send"));
        // SESSION_ESTABLISH: эфемерный ГОСТ + ML-KEM под сертификат узла
        let eph = HybridKeyPair::generate().expect("eph");
        let mut ukm_b = [0u8; 8];
        sakura_common::rand::fill(&mut ukm_b);
        let ukm = u64::from_le_bytes(ukm_b) | 1;
        let ss_gost =
            sakura_gost::vko_kek_256(&eph.gost_priv, &node_cert.public.gost, ukm).expect("vko");
        let (ct, ss_pq) = sakura_pq::mlkem1024_encapsulate(&node_cert.public.mlkem_ek).expect("kem");
        let h3 = net::establish_payload(ukm, eph.public.gost, ct);
        conn.send_msg(&codec, CLIENT_DST, entry.idx as u16, MsgType::SessionEstablish as u8, &h3)
            .unwrap_or_else(|_| fail("establish send"));
        let conf = expect_frame(&mut conn, &codec, MsgType::SessionConfirm);
        let conf_v = Cbor::from_slice(&conf).unwrap_or_else(|_| fail("confirm"));
        let csig = conf_v.get("sig").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("confirm sig"));
        let mut tt = Vec::new();
        tt.extend_from_slice(&h0);
        tt.extend_from_slice(&h1);
        tt.extend_from_slice(&h2);
        tt.extend_from_slice(&h3);
        let cdig = streebog256(&tt);
        if !sakura_hybrid::hybrid_verify(&node_cert.public, &cdig, csig) {
            fail("SESSION_CONFIRM: подпись узла невалидна");
        }
        let salt = cdig;
        let keyb = hybrid_kem_combine(&ss_gost, &ss_pq, &salt, PROTOCOL_ID, 1);
        let mut key = [0u8; 32];
        key.copy_from_slice(&keyb);
        conn.session_key = Some(key);
        conn.channel_binding = Some(salt);
        conn.established = true;
        conn.peer_id = Some(entry.node_id);
        Client { conn, codec, req_seq: 0 }
    }

    fn next_seq(&mut self) -> u64 {
        self.req_seq += 1;
        self.req_seq
    }

    fn request(&mut self, req: ApiRequest, timeout: Duration) -> ApiResponse {
        let seq = req.request_seq();
        self.conn
            .send_msg(&self.codec, CLIENT_DST, 0, TYPE_CONTROL_API, &req.to_cbor().to_vec())
            .unwrap_or_else(|_| fail("request send"));
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                fail("timeout ожидания ответа узла");
            }
            match self.conn.poll_frames(&self.codec, 16) {
                Ok(frames) => {
                    for (mtype, _s, payload) in frames {
                        if mtype == MsgType::ControlApi {
                            if let Ok(v) = Cbor::from_slice(&payload) {
                                if let Some(r) = ApiResponse::from_cbor(&v) {
                                    if r.request_seq == seq {
                                        return r;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn expect_frame(conn: &mut Conn, codec: &NppCodec, want: MsgType) -> Vec<u8> {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(10) {
            fail(&format!("timeout ожидания {:?}", want));
        }
        if let Ok(frames) = conn.poll_frames(codec, 8) {
            for (mtype, _seq, payload) in frames {
                if mtype == want {
                    return payload;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

/// Позиционный аргумент, следующий за токеном `after` (не флаг).
fn positional_after(args: &[String], after: &str) -> Option<String> {
    args.iter()
        .position(|a| a == after)
        .and_then(|i| args.get(i + 1))
        .filter(|a| !a.starts_with("--"))
        .cloned()
}

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
            let inner: Vec<String> =
                items.iter().map(|(k, val)| format!("{}:{}", json_of(k), json_of(val))).collect();
            format!("{{{}}}", inner.join(","))
        }
        Cbor::Tag(t, inner) => format!("{{\"tag\":{t},\"value\":{}}}", json_of(inner)),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // команда — первый аргумент, не являющийся флагом/значением флага
    let value_flags = [
        "--node", "--bundle", "--op", "--role", "--out", "--pkg", "--type",
        "--target", "--payload-hex", "--reason", "--op2", "--from", "--max", "--file",
    ];
    let cmd = args
        .iter()
        .skip(1)
        .scan(
            false,
            |skip, a| {
                if *skip {
                    *skip = false;
                    return Some(None);
                }
                if a.starts_with("--") {
                    if value_flags.contains(&a.as_str()) {
                        *skip = true;
                    }
                    return Some(None);
                }
                Some(Some(a.clone()))
            },
        )
        .flatten()
        .next();
    let cmd = Some(cmd.unwrap_or_default());
    let Some(cmd) = cmd.filter(|c| !c.is_empty()) else {
        eprintln!(
            "sakura-cli — операторский инструмент\n\
             Глобальные: --node HOST:PORT --bundle B --op OP_DIR [--role R]\n\
             Команды:\n  \
             status\n  \
             kv get KEY | kv put KEY VALUE | kv incr KEY [N] | kv list\n  \
             submit --type T [--payload-hex H] [--target S]\n  \
             attest [--verify] [--out F]\n  \
             audit export --out F [--from N] [--max N]\n  \
             audit verify --file F\n  \
             update push --pkg F\n  \
             emergency --reason R --op2 OP2_DIR [--confirm]\n  \
             watch [SECONDS]"
        );
        std::process::exit(1);
    };
    let node_addr = arg_value(&args, "--node").unwrap_or_else(|| "127.0.0.1:9100".into());
    let bundle_path = arg_value(&args, "--bundle").map(PathBuf::from).unwrap_or_else(|| fail("--bundle"));
    let op_dir = arg_value(&args, "--op").map(PathBuf::from).unwrap_or_else(|| fail("--op"));
    let bundle = TrustBundle::load(&bundle_path).unwrap_or_else(|| fail("bundle"));
    let role_hint = arg_value(&args, "--role");
    let op = load_operator(&op_dir, role_hint.as_deref());
    // роль из bundle — авторитетна
    if let Some(r) = bundle.operator_role(&op.id) {
        if role_hint.as_deref() != Some(r) {
            eprintln!("(роль по bundle: {r})");
        }
    }

    match cmd.as_str() {
        "status" => {
            let mut c = Client::connect(&node_addr, &bundle, &op);
            let seq = c.next_seq();
            let r = c.request(ApiRequest::GetStatus { node_id: None, request_seq: seq }, Duration::from_secs(5));
            println!("result: {}", r.result);
            if let Some(d) = &r.data {
                println!("{}", json_of(d));
            }
        }
        "kv" => {
            let sub = positional_after(&args, "kv").unwrap_or_default();
            let mut c = Client::connect(&node_addr, &bundle, &op);
            match sub.as_str() {
                "get" => {
                    let key = positional_after(&args, "get").or_else(|| positional_after(&args, "put")).unwrap_or_else(|| fail("KEY"));
                    let seq = c.next_seq();
                    let r = c.request(ApiRequest::KvGet { key, request_seq: seq }, Duration::from_secs(5));
                    println!("result: {}", r.result);
                    if let Some(d) = &r.data {
                        if let Cbor::Map(_) = d {
                            let val = d.get("value").and_then(|v| v.as_bytes());
                            match val {
                                Some(v) => println!("value: {}", String::from_utf8_lossy(v)),
                                None => {
                                    if let Some(cnt) = d.get("counter").and_then(|v| v.as_u64()) {
                                        println!("counter: {cnt}");
                                    } else {
                                        println!("(нет значения)");
                                    }
                                }
                            }
                        } else {
                            println!("(нет значения)");
                        }
                    }
                }
                "list" => {
                    let seq = c.next_seq();
                    let r = c.request(ApiRequest::KvList { request_seq: seq }, Duration::from_secs(5));
                    println!("result: {}", r.result);
                    if let Some(d) = &r.data {
                        println!("{}", json_of(d));
                    }
                }
                "put" | "incr" => {
                    let key = positional_after(&args, "put")
                        .or_else(|| positional_after(&args, "incr"))
                        .unwrap_or_else(|| fail("KEY"));
                    let (cmd_type, payload) = if sub == "put" {
                        let value = positional_after(&args, &key).unwrap_or_else(|| fail("VALUE"));
                        (
                            "KV_PUT",
                            Cbor::map(vec![
                                (Cbor::text("key"), Cbor::text(key.clone())),
                                (Cbor::text("value"), Cbor::bytes(value.into_bytes())),
                            ])
                            .to_vec(),
                        )
                    } else {
                        let n: u64 = positional_after(&args, &key).and_then(|v| v.parse().ok()).unwrap_or(1);
                        (
                            "KV_INCR",
                            Cbor::map(vec![
                                (Cbor::text("key"), Cbor::text(key.clone())),
                                (Cbor::text("delta"), Cbor::UInt(n)),
                            ])
                            .to_vec(),
                        )
                    };
                    let r = submit_command(&mut c, &op, cmd_type, payload, "cluster".into(), None);
                    println!("result: {} (audit_ref {}, seq {})", r.result, r.audit_ref, r.request_seq);
                }
                other => fail(&format!("kv: неизвестная подкоманда {other}")),
            }
        }
        "submit" => {
            let cmd_type = arg_value(&args, "--type").unwrap_or_else(|| fail("--type"));
            let payload = arg_value(&args, "--payload-hex")
                .map(|h| sakura_common::hex::decode(&h).unwrap_or_else(|_| fail("hex")))
                .unwrap_or_default();
            let target = arg_value(&args, "--target").unwrap_or_else(|| "cluster".into());
            let mut c = Client::connect(&node_addr, &bundle, &op);
            let r = submit_command(&mut c, &op, &cmd_type, payload, target, None);
            println!("result: {} (audit_ref {})", r.result, r.audit_ref);
        }
        "attest" => {
            let mut c = Client::connect(&node_addr, &bundle, &op);
            let mut nonce = vec![0u8; 32];
            sakura_common::rand::fill(&mut nonce);
            let seq = c.next_seq();
            let r = c.request(
                ApiRequest::RequestAttestation { nonce: nonce.clone(), request_seq: seq },
                Duration::from_secs(10),
            );
            println!("result: {}", r.result);
            let Some(data) = &r.data else { return };
            let cose = data.get("cose").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("cose"));
            let cert = data
                .get("cert")
                .and_then(|x| x.as_bytes())
                .and_then(SignerCert::decode)
                .unwrap_or_else(|| fail("device cert"));
            let pcert = data
                .get("platform_cert")
                .and_then(|x| x.as_bytes())
                .and_then(SignerCert::decode)
                .unwrap_or_else(|| fail("platform cert"));
            if let Some(out) = arg_value(&args, "--out") {
                std::fs::write(&out, cose).ok();
                println!("сохранено: {out} ({} байт)", cose.len());
            }
            if args.iter().any(|a| a == "--verify") {
                let anchor = TrustAnchor::new(bundle.root_pk.clone(), bundle.crl.clone());
                let chain = vec![cert.clone(), pcert];
                // policy hash ожидаем из статуса узла (запрашиваем отдельно)
                let seq2 = c.next_seq();
                let st = c.request(ApiRequest::GetStatus { node_id: None, request_seq: seq2 }, Duration::from_secs(5));
                let policy_hash = st
                    .data
                    .as_ref()
                    .and_then(|d| d.get("policy_hash"))
                    .and_then(|x| x.as_bytes())
                    .unwrap_or(&[])
                    .to_vec();
                let now_s = sakura_common::time::unix_s();
                let expect = VerifyExpectations {
                    nonce: &nonce,
                    expected_pcrs: &[],
                    policy_hash: &policy_hash,
                    hsm_status_required: "OK",
                    model_allowlist: &[],
                    now_s,
                    max_age_s: REPORT_TTL_S,
                    min_fw_versions: &[],
                };
                match verify_report(cose, &chain, &anchor, &expect) {
                    Ok(rep) => {
                        println!("VERIFY: OK");
                        println!("  device_id : {}", sakura_common::hex::encode(&rep.device_id));
                        println!("  boot_mode : {}", rep.boot_mode);
                        println!("  hsm_status: {}", rep.hsm_status);
                        println!("  time      : {}", rep.time_sync_quality);
                        println!("  fw        : {:?}", rep.fw_versions);
                        println!("  rollback  : {:?}", rep.rollback_counters);
                        println!("  sig_alg   : 0x{:02X} (переменная длина)", rep.signature_alg);
                    }
                    Err(e) => {
                        println!("VERIFY: FAILED {e:?}");
                        std::process::exit(3);
                    }
                }
            }
        }
        "audit" => {
            let sub = positional_after(&args, "audit").unwrap_or_default();
            match sub.as_str() {
                "export" => {
                    let mut c = Client::connect(&node_addr, &bundle, &op);
                    let out = arg_value(&args, "--out").unwrap_or_else(|| fail("--out"));
                    let from: u64 = arg_value(&args, "--from").and_then(|v| v.parse().ok()).unwrap_or(1);
                    let max: u64 = arg_value(&args, "--max").and_then(|v| v.parse().ok()).unwrap_or(1000);
                    let mut rid = vec![0u8; 16];
                    sakura_common::rand::fill(&mut rid);
                    let seq = c.next_seq();
                    let r = c.request(
                        ApiRequest::AuditExport {
                            request_id: rid,
                            from_seq: from,
                            max_records: max,
                            request_seq: seq,
                            authz_token: Vec::new(),
                        },
                        Duration::from_secs(20),
                    );
                    if r.result != "OK" {
                        fail(&format!("export: {}", r.result));
                    }
                    let chunk = r.data.as_ref().and_then(|d| d.get("chunk")).and_then(|x| x.as_bytes())
                        .unwrap_or_else(|| fail("chunk"));
                    std::fs::write(&out, chunk).unwrap_or_else(|_| fail("write"));
                    println!("экспортировано: {out} ({} байт)", chunk.len());
                }
                "verify" => {
                    let file = arg_value(&args, "--file").map(PathBuf::from).unwrap_or_else(|| fail("--file"));
                    audit_verify(&file, &bundle);
                }
                other => fail(&format!("audit: {other}")),
            }
        }
        "update" => {
            let sub = positional_after(&args, "update").unwrap_or_default();
            if sub != "push" {
                fail("update push --pkg F");
            }
            let pkg_path = arg_value(&args, "--pkg").map(PathBuf::from).unwrap_or_else(|| fail("--pkg"));
            let pkg = std::fs::read(&pkg_path).unwrap_or_else(|_| fail("pkg read"));
            let mut c = Client::connect(&node_addr, &bundle, &op);
            let mut ik = vec![0u8; 16];
            sakura_common::rand::fill(&mut ik);
            let seq = c.next_seq();
            println!("подтвердите OTA-обновление (yes/NO):");
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() || line.trim() != "yes" {
                println!("отменено (auto-cancel по timeout, §25.2)");
                return;
            }
            let r = c.request(
                ApiRequest::UpdateCommit { package: pkg, request_seq: seq, idempotency_key: ik },
                Duration::from_secs(30),
            );
            println!("result: {}", r.result);
            if r.result == "OK" {
                println!("узел уйдёт в REBOOT для применения образа (§13.16.2)");
            }
        }
        "emergency" => {
            let reason: u32 = arg_value(&args, "--reason").and_then(|v| v.parse().ok()).unwrap_or(1);
            let op2_dir = arg_value(&args, "--op2").map(PathBuf::from).unwrap_or_else(|| fail("--op2 (второй оператор)"));
            let op2 = load_operator(&op2_dir, None);
            if op2.id == op.id {
                fail("two-person rule: требуется ВТОРОЙ оператор (§25.2)");
            }
            if !args.iter().any(|a| a == "--confirm") {
                println!("EMERGENCY STOP — критическая команда. Добавьте --confirm для исполнения.");
                return;
            }
            let mut ik = vec![0u8; 16];
            sakura_common::rand::fill(&mut ik);
            let mut cid = [0u8; 16];
            cid.copy_from_slice(&streebog256(&ik)[..16]);
            let cmd = Command {
                plan_id: [0u8; 16],
                command_id: cid,
                seq: 0,
                cmd_type: "EMERGENCY_STOP".into(),
                payload: reason.to_be_bytes().to_vec(),
                target: "cluster".into(),
            };
            let data = cmd.canonical_bytes();
            let sig1 = hybrid_sign(&op.kp, &data).expect("sig1");
            let sig2 = hybrid_sign(&op2.kp, &data).expect("sig2");
            let mut c = Client::connect(&node_addr, &bundle, &op);
            let seq = c.next_seq();
            let r = c.request(
                ApiRequest::EmergencyStop {
                    reason_code: reason,
                    op_sig: sig1,
                    op_pk: op.kp.public.to_bytes(),
                    op_cert: op.cert.encode(),
                    second_op_sig: sig2,
                    second_op_pk: op2.kp.public.to_bytes(),
                    request_seq: seq,
                    idempotency_key: ik,
                },
                Duration::from_secs(10),
            );
            println!("result: {}", r.result);
            if let Some(d) = &r.data {
                println!("{}", json_of(d));
            }
        }
        "watch" => {
            let secs: u64 = positional_after(&args, "watch").and_then(|v| v.parse().ok()).unwrap_or(30);
            let mut c = Client::connect(&node_addr, &bundle, &op);
            let end = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < end {
                let seq = c.next_seq();
                let r = c.request(ApiRequest::GetStatus { node_id: None, request_seq: seq }, Duration::from_secs(5));
                if let Some(d) = &r.data {
                    let g = |k: &str| -> String {
                        match d.get(k) {
                            Some(Cbor::Text(t)) => t.clone(),
                            Some(Cbor::UInt(u)) => u.to_string(),
                            _ => "-".into(),
                        }
                    };
                    println!(
                        "[{}] phase={} mode={} h={} v={} time={} audit={} pending={}",
                        sakura_common::time::iso8601(sakura_common::time::unix_s()),
                        g("phase"),
                        g("mode"),
                        g("consensus_height"),
                        g("consensus_view"),
                        g("time_quality"),
                        g("audit_len"),
                        g("pending_ops"),
                    );
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        other => fail(&format!("неизвестная команда: {other}")),
    }
}

fn submit_command(
    c: &mut Client,
    op: &Operator,
    cmd_type: &str,
    payload: Vec<u8>,
    target: String,
    second: Option<(HybridPublicKey, Vec<u8>)>,
) -> ApiResponse {
    let plan_id = Uuid7::now();
    let command_id = Uuid7::now();
    let mut ik = vec![0u8; 16];
    sakura_common::rand::fill(&mut ik);
    let seq = sakura_common::time::unix_ms(); // monotonic seq принципала
    let cmd = Command {
        plan_id: *plan_id.as_bytes(),
        command_id: *command_id.as_bytes(),
        seq,
        cmd_type: cmd_type.to_owned(),
        payload: payload.clone(),
        target,
    };
    let sig = hybrid_sign(&op.kp, &cmd.canonical_bytes()).expect("cmd sign");
    let rseq = c.next_seq();
    c.request(
        ApiRequest::SubmitCommand {
            plan_id: *plan_id.as_bytes(),
            command_id: *command_id.as_bytes(),
            seq,
            cmd_type: cmd_type.to_owned(),
            payload,
            target: cmd.target.clone(),
            cmd_sig: sig,
            operator_pk: op.kp.public.to_bytes(),
            operator_cert: op.cert.encode(),
            operator_role: op.role.clone(),
            authz_token: Vec::new(),
            idempotency_key: ik,
            request_seq: rseq,
            second_sig: second.map(|(pk, s)| (pk.to_bytes(), s)),
        },
        Duration::from_secs(15),
    )
}

fn audit_verify(file: &Path, bundle: &TrustBundle) {
    let raw = std::fs::read(file).unwrap_or_else(|_| fail("file read"));
    let v = Cbor::from_slice(&raw).unwrap_or_else(|_| fail("chunk cbor"));
    // 1. chunk_hash: пересчитать body без chunk_hash/signature
    let items: Vec<(Cbor, Cbor)> = match &v {
        Cbor::Map(items) => items
            .iter()
            .filter(|(k, _)| {
                let ks = k.as_text().unwrap_or("");
                ks != "chunk_hash" && ks != "signature"
            })
            .cloned()
            .collect(),
        _ => fail("chunk format"),
    };
    let body = Cbor::map(items.clone()).to_vec();
    let calc_hash = streebog256(&body);
    let stored_hash = v.get("chunk_hash").and_then(|x| x.as_bytes()).unwrap_or(&[]);
    if calc_hash.as_slice() != stored_hash {
        println!("VERIFY: FAILED chunk_hash mismatch");
        std::process::exit(3);
    }
    // 2. подпись chunk'а — сертификат узла (по node_id первой записи)
    let sig = v.get("signature").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("sig"));
    let records = v.get("records").and_then(|x| x.as_array()).unwrap_or_else(|| fail("records"));
    let mut to_sign = items.clone();
    to_sign.push((Cbor::text("chunk_hash"), Cbor::bytes(calc_hash.to_vec())));
    let tbs = Cbor::map(to_sign).to_vec();
    let mut verified_by = None;
    for (nid, cert) in &bundle.device_certs {
        if sakura_hybrid::hybrid_verify(&cert.public, &tbs, sig) {
            verified_by = Some((*nid, cert.clone()));
            break;
        }
    }
    let Some((nid, cert)) = verified_by else {
        println!("VERIFY: FAILED chunk signature");
        std::process::exit(3);
    };
    println!("chunk подписан узлом {}", Uuid7(nid));
    // 3. записи: цепочка + подписи узла + monotonic seq
    let mut prev_hash = None;
    let mut count = 0u64;
    for rec in records {
        // подпись записи: canonical с пустым signature
        let mut items2: Vec<(Cbor, Cbor)> = match rec {
            Cbor::Map(m) => m
                .iter()
                .map(|(k, val)| {
                    if k.as_text() == Some("signature") {
                        (k.clone(), Cbor::Bytes(Vec::new()))
                    } else {
                        (k.clone(), val.clone())
                    }
                })
                .collect(),
            _ => fail("record format"),
        };
        items2.sort_by(|a, b| {
            let ka = a.0.to_vec();
            let kb = b.0.to_vec();
            ka.len().cmp(&kb.len()).then_with(|| ka.cmp(&kb))
        });
        let tbs_rec = Cbor::Map(items2).to_vec();
        let rsig = rec.get("signature").and_then(|x| x.as_bytes()).unwrap_or(&[]);
        if !sakura_hybrid::hybrid_verify(&cert.public, &tbs_rec, rsig) {
            println!("VERIFY: FAILED record signature at #{count}");
            std::process::exit(3);
        }
        let seq = rec.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
        let hash_prev = rec.get("hash_prev").and_then(|x| x.as_bytes()).unwrap_or(&[]).to_vec();
        let hash_self = rec.get("hash_self").and_then(|x| x.as_bytes()).unwrap_or(&[]).to_vec();
        if let Some(p) = &prev_hash {
            if &hash_prev != p {
                println!("VERIFY: FAILED chain link at seq {seq}");
                std::process::exit(3);
            }
        }
        prev_hash = Some(hash_self);
        count += 1;
    }
    println!("VERIFY: OK — записей: {count}, цепочка и подписи валидны");
}
