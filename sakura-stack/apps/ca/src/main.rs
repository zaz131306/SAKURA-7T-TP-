//! sakura-ca — PKI/ceremony-инструмент (§23.4 PKI, §23.9 key ceremony,
//! §22.18 key provisioning).
//!
//! Команды:
//! - `init --dir CA --cluster-n N` — корневой и промежуточные ключи;
//! - `gen-node --dir CA --out NODE --idx I --host H --port P --http-port HP`
//!   — идентичность узла (ключи генерируются ВНУТРИ SoftHsm-образа,
//!   экспорт только публичной части — §13.6 no raw private key export);
//! - `gen-operator --dir CA --out OP --role R` — оператор (two-person, RBAC);
//! - `sign-image --dir CA --payload F --type T --version V --rollback R --out IMG`;
//! - `ota-package --dir CA --image IMG --type T --version V --rollback R --out PKG`;
//! - `policy-hash` — отпечаток PolicyDoc по умолчанию (OTA policy binding);
//! - `revoke --dir CA --cert F` — CRL (§23.14);
//! - `show --dir CA` — дамп bundle.
//!
//! Production: ключи корня — offline HSM, dual control, split knowledge
//! n=5/k=3 (§23.7, §23.9). Данный инструмент — SIL-эмуляция ceremony с
//! документированным risk acceptance; формат артефактов идентичен.
#![forbid(unsafe_code)]

use sakura_boot::bundle::{RosterEntry, TrustBundle};
use sakura_boot::cert::{
    key_id_of_pub, SignerCert, USAGE_CA, USAGE_DEVICE_IDENTITY, USAGE_FIRMWARE_SIGN,
    USAGE_OPERATOR, USAGE_UPDATE_SIGN,
};
use sakura_boot::image::{
    ImageHeader, ALG_GOST_PLUS_MLDSA65, ALG_STREEBOG_256, FLAG_ROLLBACK, FLAG_SIGNED, IMAGE_TYPE_APP, IMAGE_TYPE_BOOTLOADER, IMAGE_TYPE_KERNEL, IMAGE_TYPE_MODEL,
};
use sakura_common::cbor::Cbor;
use sakura_common::uuid7::Uuid7;
use sakura_gost::hash::streebog256;
use sakura_hsm::soft::SoftHsm;
use sakura_hsm::{HsmBackend, KEY_CLASS_DEVICE_IDENTITY, KEY_TYPE_HYBRID_SIGN};
use sakura_hybrid::{hybrid_sign, HybridKeyPair, HybridPublicKey};
use sakura_boot::rollback::RollbackStore;
use sakura_update::{SlotStorage, UpdateManifest, UpdatePackage};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CERT_TTL_S: u64 = 3 * 365 * 24 * 3600; // L2: 1–3 года (§23.6)
const NODE_PIN_DEFAULT: &str = "sakura-node-pin";

fn fail(msg: &str) -> ! {
    eprintln!("sakura-ca: {msg}");
    std::process::exit(1);
}

// ---------------- хранение ключей CA ----------------

fn save_keypair(dir: &Path, name: &str, kp: &HybridKeyPair) {
    let doc = Cbor::map(vec![
        (Cbor::text("gost"), Cbor::bytes(kp.gost_priv.to_vec())),
        (Cbor::text("mldsa"), Cbor::bytes(kp.mldsa_sk.clone())),
        (Cbor::text("mlkem"), Cbor::bytes(kp.mlkem_dk.clone())),
        (Cbor::text("pub"), Cbor::bytes(kp.public.to_bytes())),
    ]);
    let p = dir.join(format!("{name}.key"));
    std::fs::write(&p, doc.to_vec()).unwrap_or_else(|_| fail("key write"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
}

fn load_keypair(dir: &Path, name: &str) -> HybridKeyPair {
    let raw = std::fs::read(dir.join(format!("{name}.key")))
        .unwrap_or_else(|_| fail(&format!("key {name} not found — выполните init")));
    let v = Cbor::from_slice(&raw).unwrap_or_else(|_| fail("key corrupt"));
    let mut gost_priv = [0u8; 32];
    gost_priv.copy_from_slice(v.get("gost").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")));
    let mldsa_sk = v.get("mldsa").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")).to_vec();
    let mlkem_dk = v.get("mlkem").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key")).to_vec();
    let pub_b = v.get("pub").and_then(|x| x.as_bytes()).unwrap_or_else(|| fail("key"));
    let public = HybridPublicKey::from_bytes(pub_b).unwrap_or_else(|| fail("pub"));
    HybridKeyPair { gost_priv, mldsa_sk, mlkem_dk, public }
}

fn save_cert(dir: &Path, name: &str, cert: &SignerCert) {
    std::fs::write(dir.join(format!("{name}.cert")), cert.encode())
        .unwrap_or_else(|_| fail("cert write"));
}

fn load_cert(dir: &Path, name: &str) -> SignerCert {
    let raw = std::fs::read(dir.join(format!("{name}.cert")))
        .unwrap_or_else(|_| fail(&format!("cert {name} not found")));
    SignerCert::decode(&raw).unwrap_or_else(|| fail("cert corrupt"))
}

fn load_bundle(dir: &Path) -> TrustBundle {
    TrustBundle::load(&dir.join("bundle.cbor")).unwrap_or_else(|| fail("bundle not found — init?"))
}

fn save_bundle(dir: &Path, b: &TrustBundle) {
    b.save(&dir.join("bundle.cbor")).unwrap_or_else(|_| fail("bundle write"));
}

/// Bundle для каталога узла — имя trust_bundle.cbor (NodeConfig::bundle_path).
fn save_bundle_for_node(dir: &Path, b: &TrustBundle) {
    b.save(&dir.join("trust_bundle.cbor")).unwrap_or_else(|_| fail("bundle write"));
}

fn issue_cert(
    issuer: &HybridKeyPair,
    issuer_cert_keyid: [u8; 16],
    subject_pub: &HybridPublicKey,
    subject_id: [u8; 16],
    usage: u8,
    hw_rev_min: u16,
) -> SignerCert {
    let now = sakura_common::time::unix_s();
    let mut c = SignerCert {
        subject_id,
        signer_id: issuer_cert_keyid,
        public: subject_pub.clone(),
        key_usage: usage,
        hw_rev_min,
        not_before: now.saturating_sub(60),
        not_after: now + CERT_TTL_S,
        signature: Vec::new(),
    };
    c.signature = hybrid_sign(issuer, &c.tbs()).expect("issue cert");
    c
}

// ---------------- команды ----------------

fn cmd_init(dir: &Path, cluster_n: u32) {
    std::fs::create_dir_all(dir).ok();
    if dir.join("root.key").exists() {
        fail("CA уже инициализирована (root.key существует)");
    }
    eprintln!("== Key ceremony (§23.9): генерация корневых ключей ==");
    let root = HybridKeyPair::generate().expect("root keygen");
    let platform = HybridKeyPair::generate().expect("platform keygen");
    let firmware = HybridKeyPair::generate().expect("fw keygen");
    let update = HybridKeyPair::generate().expect("upd keygen");
    save_keypair(dir, "root", &root);
    save_keypair(dir, "platform", &platform);
    save_keypair(dir, "firmware", &firmware);
    save_keypair(dir, "update", &update);

    let now = sakura_common::time::unix_s();
    // self-signed root (L0, offline HSM)
    let root_id = Uuid7::now();
    let mut root_cert = SignerCert {
        subject_id: *root_id.as_bytes(),
        signer_id: key_id_of_pub(&root.public),
        public: root.public.clone(),
        key_usage: USAGE_CA,
        hw_rev_min: 0,
        not_before: now.saturating_sub(60),
        not_after: now + 10 * 365 * 24 * 3600, // L0: 10 лет (§23.6)
        signature: Vec::new(),
    };
    root_cert.signature = hybrid_sign(&root, &root_cert.tbs()).expect("root self-sign");
    save_cert(dir, "root", &root_cert);

    let platform_cert = issue_cert(
        &root,
        key_id_of_pub(&root.public),
        &platform.public,
        *Uuid7::now().as_bytes(),
        USAGE_CA,
        0,
    );
    save_cert(dir, "platform", &platform_cert);
    let fw_cert = issue_cert(
        &platform,
        key_id_of_pub(&platform.public),
        &firmware.public,
        *Uuid7::now().as_bytes(),
        USAGE_FIRMWARE_SIGN,
        1,
    );
    save_cert(dir, "firmware", &fw_cert);
    let upd_cert = issue_cert(
        &platform,
        key_id_of_pub(&platform.public),
        &update.public,
        *Uuid7::now().as_bytes(),
        USAGE_UPDATE_SIGN,
        1,
    );
    save_cert(dir, "update", &upd_cert);

    let bundle = TrustBundle {
        root_pk: root.public.clone(),
        platform_cert: platform_cert.clone(),
        firmware_cert: fw_cert,
        update_cert: upd_cert,
        device_certs: BTreeMap::new(),
        operator_certs: BTreeMap::new(),
        crl: Vec::new(),
        roster: Vec::new(),
    };
    save_bundle(dir, &bundle);
    std::fs::write(dir.join("cluster_n"), cluster_n.to_string()).ok();
    eprintln!("CA создана: {}/ (root → platform → firmware/update)", dir.display());
}

fn cmd_gen_node(ca: &Path, out: &Path, idx: u32, host: &str, port: u16, http_port: u16, hw_rev: u16) {
    let mut bundle = load_bundle(ca);
    if bundle.roster.iter().any(|r| r.idx == idx) {
        fail(&format!("roster idx {idx} уже занят"));
    }
    std::fs::create_dir_all(out.join("identity")).ok();
    std::fs::create_dir_all(out.join("flash")).ok();
    std::fs::create_dir_all(out.join("audit")).ok();

    // идентичность генерируется ВНУТРИ HSM-образа (§22.18 factory)
    let pin_file = out.join("hsm.pin");
    std::fs::write(&pin_file, NODE_PIN_DEFAULT).ok();
    let mut hsm = SoftHsm::new(NODE_PIN_DEFAULT.as_bytes()).expect("hsm");
    let sid = hsm.open_session(NODE_PIN_DEFAULT.as_bytes()).expect("session");
    let mut key_handle = 0u32;
    hsm.generate_key(sid, &[KEY_TYPE_HYBRID_SIGN, KEY_CLASS_DEVICE_IDENTITY], &mut key_handle)
        .expect("generate");
    assert_eq!(key_handle, 1);
    let pub_bytes = hsm.export_public_key(key_handle).expect("pub export");
    let device_pub = HybridPublicKey::from_bytes(&pub_bytes).expect("pub");
    hsm.save_keystore(&out.join("identity").join("keystore.bin"), NODE_PIN_DEFAULT.as_bytes())
        .expect("keystore save");

    let node_id = Uuid7::now();
    let platform_kp = load_keypair(ca, "platform");
    let platform_cert = load_cert(ca, "platform");
    let device_cert = issue_cert(
        &platform_kp,
        key_id_of_pub(&platform_cert.public),
        &device_pub,
        *node_id.as_bytes(),
        USAGE_DEVICE_IDENTITY,
        hw_rev,
    );
    bundle.device_certs.insert(*node_id.as_bytes(), device_cert);
    bundle.roster.push(RosterEntry {
        idx,
        node_id: *node_id.as_bytes(),
        host: host.to_owned(),
        port,
        http_port,
    });
    save_bundle(ca, &bundle);
    // копия bundle узлу
    save_bundle_for_node(out, &bundle);

    // образы PBL/SBL/KERNEL (подписаны firmware CA)
    let fw_kp = load_keypair(ca, "firmware");
    let fw_cert = load_cert(ca, "firmware");
    let chain: Vec<u8> = sakura_boot::cert::encode_chain(&[fw_cert, platform_cert.clone()]);
    let build_id = format!("sakura-2.3.0-idx{idx}");
    let pbl = build_signed_image(&fw_kp, &chain, 1, IMAGE_TYPE_BOOTLOADER, 0, hw_rev, format!("{build_id}-pbl").as_bytes());
    let sbl = build_signed_image(&fw_kp, &chain, 1, IMAGE_TYPE_BOOTLOADER, 0, hw_rev, format!("{build_id}-sbl").as_bytes());
    let kernel = build_signed_image(&fw_kp, &chain, 1, IMAGE_TYPE_KERNEL, 0, hw_rev, format!("{build_id}-kernel-v2.3.0").as_bytes());
    std::fs::write(out.join("flash").join("pbl.img"), &pbl).expect("pbl");
    std::fs::write(out.join("flash").join("sbl.img"), &sbl).expect("sbl");
    // A/B slot 0 + rollback store
    let mac_key = rollback_mac_key(NODE_PIN_DEFAULT);
    let rb = RollbackStore::new(mac_key);
    SlotStorage::provision_initial(out.join("flash"), &kernel, 1, [4u8; 32], rb).expect("slot0");

    // config.ini
    let cluster_n: u32 = std::fs::read_to_string(ca.join("cluster_n"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(4);
    let ini = format!(
        "; SAKURA STACK node configuration (CM-1 §25.6)\n\
         [node]\nidx = {idx}\nid = {nid}\nhw_rev = {hw}\nlisten = {host}:{port}\nhttp = {host}:{http_port}\ndata_dir = {dd}\n\
         [cluster]\nn = {cluster_n}\nmode = bft\n\
         [hsm]\npin_file = {pin}\n\
         [consensus]\nround_ms = 250\nheartbeat_ms = 500\nproposer_timeout_ms = 2000\npeer_timeout_ms = 3000\n\
         [watchdog]\nmin_ms = 50\nmax_ms = 200\n\
         [time]\nsync_interval_ms = 1000\ndrift_ppb_x1000 = 58\n\
         [audit]\nsign_records = true\n",
        nid = sakura_common::hex::encode(node_id.as_bytes()),
        hw = hw_rev,
        dd = out.display(),
        pin = pin_file.display(),
    );
    std::fs::write(out.join("config.ini"), ini).expect("config");
    eprintln!(
        "узел {idx} provisioned: {} (node_id {node_id}, listen {host}:{port}, http {host}:{http_port})",
        out.display()
    );
}

fn rollback_mac_key(pin: &str) -> [u8; 32] {
    sakura_gost::kdf::kdf_gostr3411_2012_256(
        &streebog256(pin.as_bytes()),
        b"ROLLBACK-STORE",
        b"SAKURA-V1",
    )
}

fn build_signed_image(
    signer: &HybridKeyPair,
    chain_cbor: &[u8],
    version: u32,
    image_type: u8,
    rollback: u32,
    min_hw_rev: u16,
    payload: &[u8],
) -> Vec<u8> {
    let h = ImageHeader {
        version,
        min_hw_rev,
        image_type,
        flags: FLAG_SIGNED | FLAG_ROLLBACK,
        payload_size: payload.len() as u32,
        payload_hash_alg: ALG_STREEBOG_256,
        payload_hash: {
            let mut x = [0u8; 64];
            x[..32].copy_from_slice(&streebog256(payload));
            x
        },
        signer_id: [0u8; 16], // заполняется ниже (subject firmware cert)
        signature_alg: ALG_GOST_PLUS_MLDSA65,
        rollback_counter: rollback,
        timestamp: sakura_common::time::unix_s(),
    };
    // signer_id = subject_id leaf-сертификата цепочки
    let chain = {
        let v = Cbor::from_slice(chain_cbor).expect("chain");
        let arr = v.as_array().expect("chain arr");
        SignerCert::from_cbor(&arr[0]).expect("leaf cert")
    };
    let mut h = h;
    h.signer_id = chain.subject_id;
    let _ = IMAGE_TYPE_MODEL;
    let hdr = h.header_bytes(chain_cbor.len() as u16, sakura_hybrid::HYBRID_SIG_LEN as u16);
    let mut img = Vec::new();
    img.extend_from_slice(&hdr);
    img.extend_from_slice(payload);
    img.extend_from_slice(chain_cbor);
    let sig_data = sakura_boot::image::image_sign_data(&hdr, payload);
    let sig = hybrid_sign(signer, &sig_data).expect("image sign");
    img.extend_from_slice(&sig);
    img
}

fn cmd_gen_operator(ca: &Path, out: &Path, role: &str) {
    let mut bundle = load_bundle(ca);
    if !matches!(role, "ADMIN" | "OPERATOR" | "AUDITOR" | "SAFETY_OFFICER" | "SERVICE") {
        fail("роль: ADMIN|OPERATOR|AUDITOR|SAFETY_OFFICER|SERVICE");
    }
    std::fs::create_dir_all(out).ok();
    let kp = HybridKeyPair::generate().expect("op keygen");
    let pid = Uuid7::now();
    let platform_kp = load_keypair(ca, "platform");
    let platform_cert = load_cert(ca, "platform");
    let cert = issue_cert(
        &platform_kp,
        key_id_of_pub(&platform_cert.public),
        &kp.public,
        *pid.as_bytes(),
        USAGE_OPERATOR,
        0,
    );
    bundle.operator_certs.insert(*pid.as_bytes(), (cert.clone(), role.to_owned()));
    save_bundle(ca, &bundle);
    save_cert(out, "operator", &cert);
    save_keypair(out, "operator", &kp);
    std::fs::write(out.join("operator.id"), pid.to_string()).ok();
    eprintln!("оператор {role} создан: {} (id {pid})", out.display());
}

fn cmd_sign_image(ca: &Path, payload: &Path, image_type: u8, version: u32, rollback: u32, out: &Path) {
    let data = std::fs::read(payload).unwrap_or_else(|_| fail("payload read"));
    let fw_kp = load_keypair(ca, "firmware");
    let fw_cert = load_cert(ca, "firmware");
    let platform_cert = load_cert(ca, "platform");
    let chain = sakura_boot::cert::encode_chain(&[fw_cert, platform_cert]);
    let img = build_signed_image(&fw_kp, &chain, version, image_type, rollback, 1, &data);
    std::fs::write(out, &img).unwrap_or_else(|_| fail("image write"));
    eprintln!("образ подписан: {} ({} байт)", out.display(), img.len());
}

fn cmd_ota_package(ca: &Path, image: &Path, image_type: u8, version: u32, rollback: u32, policy_hash_hex: &str, out: &Path) {
    let img = std::fs::read(image).unwrap_or_else(|_| fail("image read"));
    let upd_kp = load_keypair(ca, "update");
    let ph = sakura_common::hex::decode(policy_hash_hex).unwrap_or_else(|_| fail("policy-hash hex"));
    if ph.len() != 32 {
        fail("policy-hash — 32 байта");
    }
    let mut nonce = vec![0u8; 32];
    sakura_common::rand::fill(&mut nonce);
    let manifest = UpdateManifest {
        image_type,
        version,
        rollback_counter: rollback,
        payload_hash: streebog256(&img),
        min_hw_rev: 1,
        timestamp: sakura_common::time::unix_s(),
        nonce,
        expected_policy_hash: ph,
        signature_alg: ALG_GOST_PLUS_MLDSA65,
    };
    let signature = hybrid_sign(&upd_kp, &manifest.tbs()).expect("manifest sign");
    let pkg = UpdatePackage { manifest, signature, payload: img };
    std::fs::write(out, pkg.encode()).unwrap_or_else(|_| fail("package write"));
    eprintln!("OTA-пакет: {} (type {image_type}, v{version}, rollback {rollback})", out.display());
}

fn cmd_revoke(ca: &Path, cert_file: &Path) {
    let mut bundle = load_bundle(ca);
    let raw = std::fs::read(cert_file).unwrap_or_else(|_| fail("cert read"));
    let cert = SignerCert::decode(&raw).unwrap_or_else(|| fail("cert decode"));
    let kid = cert.subject_key_id();
    if !bundle.crl.contains(&kid) {
        bundle.crl.push(kid);
    }
    bundle.device_certs.retain(|_, c| c.subject_key_id() != kid);
    bundle.operator_certs.retain(|_, (c, _)| c.subject_key_id() != kid);
    save_bundle(ca, &bundle);
    eprintln!("отозван: {} (CRL: {} записей)", sakura_common::hex::encode(&kid), bundle.crl.len());
}

fn cmd_deploy_bundle(ca: &Path, node_dirs: Vec<PathBuf>) {
    let b = load_bundle(ca);
    for d in node_dirs {
        save_bundle_for_node(&d, &b);
        eprintln!("bundle → {}", d.display());
    }
}

fn cmd_show(ca: &Path) {
    let b = load_bundle(ca);
    println!("root key id : {}", sakura_common::hex::encode(&key_id_of_pub(&b.root_pk)));
    println!("platform    : {}", sakura_common::hex::encode(&b.platform_cert.subject_key_id()));
    println!("firmware    : {}", sakura_common::hex::encode(&b.firmware_cert.subject_key_id()));
    println!("update      : {}", sakura_common::hex::encode(&b.update_cert.subject_key_id()));
    println!("devices     : {}", b.device_certs.len());
    for (id, c) in &b.device_certs {
        println!("  {} kid={}", Uuid7(*id), sakura_common::hex::encode(&c.subject_key_id()));
    }
    println!("operators   : {}", b.operator_certs.len());
    for (id, (_, role)) in &b.operator_certs {
        println!("  {} role={role}", Uuid7(*id));
    }
    println!("crl         : {}", b.crl.len());
    println!("roster      :");
    for r in &b.roster {
        println!("  idx={} {}:{} http={} node_id={}", r.idx, r.host, r.port, r.http_port, Uuid7(r.node_id));
    }
}

fn cmd_policy_hash() {
    let doc = sakura_policy::PolicyDoc::default();
    println!("{}", sakura_common::hex::encode(&doc.policy_hash()));
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn image_type_of(s: &str) -> u8 {
    match s {
        "bootloader" => IMAGE_TYPE_BOOTLOADER,
        "kernel" => IMAGE_TYPE_KERNEL,
        "app" => IMAGE_TYPE_APP,
        "model" => IMAGE_TYPE_MODEL,
        _ => fail("type: bootloader|kernel|app|model"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1) else {
        eprintln!(
            "sakura-ca — PKI/ceremony tool (§23.4/§23.9)\n\
             Команды:\n  \
             init --dir CA [--cluster-n N]\n  \
             gen-node --dir CA --out NODE --idx I --host H --port P --http-port HP [--hw-rev R]\n  \
             gen-operator --dir CA --out OP --role R\n  \
             sign-image --dir CA --payload F --type T --version V --rollback R --out IMG\n  \
             ota-package --dir CA --image IMG --type T --version V --rollback R --policy-hash H --out PKG\n  \
             policy-hash\n  \
             revoke --dir CA --cert F\n  \
             show --dir CA"
        );
        std::process::exit(1);
    };
    let ca = arg_value(&args, "--dir").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("ca"));
    match cmd.as_str() {
        "init" => {
            let n: u32 = arg_value(&args, "--cluster-n").and_then(|v| v.parse().ok()).unwrap_or(4);
            cmd_init(&ca, n);
        }
        "gen-node" => {
            let out = arg_value(&args, "--out").map(PathBuf::from).unwrap_or_else(|| fail("--out"));
            let idx: u32 = arg_value(&args, "--idx").and_then(|v| v.parse().ok()).unwrap_or_else(|| fail("--idx"));
            let host = arg_value(&args, "--host").unwrap_or_else(|| "127.0.0.1".into());
            let port: u16 = arg_value(&args, "--port").and_then(|v| v.parse().ok()).unwrap_or_else(|| fail("--port"));
            let http_port: u16 =
                arg_value(&args, "--http-port").and_then(|v| v.parse().ok()).unwrap_or_else(|| fail("--http-port"));
            let hw: u16 = arg_value(&args, "--hw-rev").and_then(|v| v.parse().ok()).unwrap_or(1);
            cmd_gen_node(&ca, &out, idx, &host, port, http_port, hw);
        }
        "gen-operator" => {
            let out = arg_value(&args, "--out").map(PathBuf::from).unwrap_or_else(|| fail("--out"));
            let role = arg_value(&args, "--role").unwrap_or_else(|| "OPERATOR".into());
            cmd_gen_operator(&ca, &out, &role);
        }
        "sign-image" => {
            let payload = arg_value(&args, "--payload").map(PathBuf::from).unwrap_or_else(|| fail("--payload"));
            let t = arg_value(&args, "--type").unwrap_or_else(|| "kernel".into());
            let v: u32 = arg_value(&args, "--version").and_then(|x| x.parse().ok()).unwrap_or(1);
            let r: u32 = arg_value(&args, "--rollback").and_then(|x| x.parse().ok()).unwrap_or(0);
            let out = arg_value(&args, "--out").map(PathBuf::from).unwrap_or_else(|| fail("--out"));
            cmd_sign_image(&ca, &payload, image_type_of(&t), v, r, &out);
        }
        "ota-package" => {
            let image = arg_value(&args, "--image").map(PathBuf::from).unwrap_or_else(|| fail("--image"));
            let t = arg_value(&args, "--type").unwrap_or_else(|| "kernel".into());
            let v: u32 = arg_value(&args, "--version").and_then(|x| x.parse().ok()).unwrap_or(2);
            let r: u32 = arg_value(&args, "--rollback").and_then(|x| x.parse().ok()).unwrap_or(1);
            let ph = arg_value(&args, "--policy-hash").unwrap_or_else(|| fail("--policy-hash"));
            let out = arg_value(&args, "--out").map(PathBuf::from).unwrap_or_else(|| fail("--out"));
            cmd_ota_package(&ca, &image, image_type_of(&t), v, r, &ph, &out);
        }
        "policy-hash" => cmd_policy_hash(),
        "deploy-bundle" => {
            let mut dirs = Vec::new();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--node" {
                    if let Some(d) = args.get(i + 1) {
                        dirs.push(PathBuf::from(d));
                        i += 2;
                        continue;
                    }
                }
                i += 1;
            }
            if dirs.is_empty() {
                fail("deploy-bundle --node DIR [--node DIR …]");
            }
            cmd_deploy_bundle(&ca, dirs);
        }
        "revoke" => {
            let cert = arg_value(&args, "--cert").map(PathBuf::from).unwrap_or_else(|| fail("--cert"));
            cmd_revoke(&ca, &cert);
        }
        "show" => cmd_show(&ca),
        other => fail(&format!("неизвестная команда: {other}")),
    }
}
