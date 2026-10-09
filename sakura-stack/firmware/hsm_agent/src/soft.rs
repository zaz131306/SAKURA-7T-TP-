//! SoftHsm — программная эмуляция HSM-контура (SIL/HIL-стенд).
//!
//! Соответствие требованиям:
//! - §13.6: rate limiting ≤10 000 операций/с, ≤1000 сессий/с; no raw private
//!   key export (публичные части — через [`SoftHsm::export_public_key`]);
//! - BC-18: все данные — в буферы вызывающей стороны, BufferTooSmall;
//!   секретные буферы обнуляются (zeroize);
//! - §22.7/23.8: Power-On self-test (KAT Стрибог + ГОСТ 34.10 + MGM + wrap),
//!   провал → SelfTestFailed-lockdown;
//! - §22.20: tamper → zeroization волатильных ключей, операции блокируются
//!   до ceremony-сброса;
//! - §23.6: классы ключей L2/L4/L5/L7, epoch инкрементируется при
//!   rotation/zeroize.
//!
//! Production: сертифицированный HSM класса КС3 (BC-16, КР-4). SoftHsm —
//! функциональный эквивалент для автономных испытаний и прототипа с
//! документированным risk acceptance (§23.8: оценённый ГПСЧ — только
//! prototype; здесь — ОС-энтропия).

use crate::{HsmBackend, HsmError, KeyHandle, SessionId};
use sakura_common::cbor::Cbor;
use sakura_common::hex;
use sakura_gost::hash::streebog256;
use sakura_gost::kdf::hkdf_streebog256;
use sakura_hybrid::{
    mgm_decrypt, mgm_encrypt, HybridKeyPair, HybridPublicKey, MGM_IV_LEN,
};
use std::collections::BTreeMap;
use std::time::Instant;

pub const SOFT_HSM_FW: &str = "SoftHsm-2.3.0/SIL";
/// Размер гибридной подписи (ГОСТ 64 + ML-DSA-65 3309), §13.7.
pub const HYBRID_SIG_SIZE: usize = sakura_hybrid::HYBRID_SIG_LEN;
const MGM_OVERHEAD: usize = MGM_IV_LEN + sakura_hybrid::MGM_TAG_LEN;

#[derive(Clone)]
struct Session {
    opened_ms: u64,
}

enum KeyMaterial {
    Hybrid(Box<HybridKeyPair>),
    Symmetric(Vec<u8>),
    Zeroized,
}

struct KeySlot {
    class: u8,
    key_type: u8,
    epoch: u32,
    material: KeyMaterial,
    /// Публичная часть (для сертификатов) — только Hybrid.
    public: Option<Vec<u8>>,
}

pub struct SoftHsm {
    pin_hash: [u8; 32],
    sessions: BTreeMap<SessionId, Session>,
    next_sid: SessionId,
    keys: BTreeMap<KeyHandle, KeySlot>,
    next_handle: KeyHandle,
    start: Instant,
    // rate limiting (§13.6)
    ops_window_start_ms: u64,
    ops_in_window: u32,
    sess_window_start_ms: u64,
    sess_in_window: u32,
    ops_limit_per_s: u32,
    sess_limit_per_s: u32,
    /// Максимальный срок сессии, с (DM-1: expires_at ≤ 1 ч, уровень L4).
    max_session_s: u64,
    // состояния
    tampered: bool,
    self_test_passed: bool,
    failed_pins: u32,
}

impl SoftHsm {
    /// Создание с master-PIN; выполняет Power-On self-test (§22.7).
    pub fn new(pin: &[u8]) -> Result<Self, HsmError> {
        let mut h = SoftHsm {
            pin_hash: streebog256(pin),
            sessions: BTreeMap::new(),
            next_sid: 1,
            keys: BTreeMap::new(),
            next_handle: 1,
            start: Instant::now(),
            ops_window_start_ms: 0,
            ops_in_window: 0,
            sess_window_start_ms: 0,
            sess_in_window: 0,
            ops_limit_per_s: 10_000,
            sess_limit_per_s: 1_000,
            max_session_s: 3600,
            tampered: false,
            self_test_passed: false,
            failed_pins: 0,
        };
        h.self_test()?;
        Ok(h)
    }

    pub fn set_rate_limits(&mut self, ops_per_s: u32, sessions_per_s: u32) {
        self.ops_limit_per_s = ops_per_s;
        self.sess_limit_per_s = sessions_per_s;
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Power-On / периодический self-test (§22.7, §21.6 п.15 crypto self-test
    /// gating). Провал → lockdown до перезапуска ceremony.
    pub fn self_test(&mut self) -> Result<(), HsmError> {
        self.self_test_passed = false;
        // 1. Стрибог-256 KAT (gostcrypto-вектор)
        let d = streebog256(b"Test message");
        if hex::encode(&d)
            != "9acca1ceba8a7beffa71aec00b438cfd8b26ada43a9496043a4a842c89f45ba7"
        {
            return Err(HsmError::SelfTestFailed);
        }
        // 2. ГОСТ 34.10-2012 sign/verify KAT (независимая реализация gostcrypto)
        let v = &sakura_gost::kat::SIG_VECS[0];
        let mut privk = [0u8; 32];
        privk.copy_from_slice(&hex::decode(v.priv_).unwrap());
        let mut pubk = [0u8; 64];
        pubk.copy_from_slice(&hex::decode(v.pub_).unwrap());
        let mut k = [0u8; 32];
        k.copy_from_slice(&hex::decode(v.rand_k).unwrap());
        let msg = hex::decode(v.msg).unwrap();
        let digest = streebog256(&msg);
        let sig = sakura_gost::gost3410::sign_deterministic(&privk, &digest, &k)
            .map_err(|_| HsmError::SelfTestFailed)?;
        if hex::encode(&sig) != v.sig || !sakura_gost::gost3410::verify(&pubk, &digest, &sig) {
            return Err(HsmError::SelfTestFailed);
        }
        // 3. MGM AEAD roundtrip KAT
        let key = [7u8; 32];
        let iv = [0u8; 16];
        let ct = mgm_encrypt(&key, &iv, b"self-test", b"payload").map_err(|_| HsmError::SelfTestFailed)?;
        let pt = mgm_decrypt(&key, &iv, b"self-test", &ct).map_err(|_| HsmError::SelfTestFailed)?;
        if pt != b"payload" {
            return Err(HsmError::SelfTestFailed);
        }
        // 4. Wrap/unwrap roundtrip (RFC 7836 §4.6)
        let ke = [1u8; 32];
        let km = [2u8; 32];
        let seed = [3u8; 8];
        let wrapped =
            sakura_gost::gost28147::wrap_key(&ke, &km, &seed).map_err(|_| HsmError::SelfTestFailed)?;
        let unwrapped = sakura_gost::gost28147::unwrap_key(&ke, &wrapped)
            .map_err(|_| HsmError::SelfTestFailed)?;
        if unwrapped != km {
            return Err(HsmError::SelfTestFailed);
        }
        self.self_test_passed = true;
        Ok(())
    }

    /// Tamper-событие (§22.20): zeroization волатильных ключей + блокировка.
    pub fn trigger_tamper(&mut self) {
        self.tampered = true;
        for slot in self.keys.values_mut() {
            slot.material = KeyMaterial::Zeroized;
            slot.public = None;
            slot.epoch = slot.epoch.wrapping_add(1);
        }
        self.sessions.clear();
    }

    /// Сброс tamper-состояния — только по ceremony (§22.20, dual control).
    pub fn ceremony_reset(&mut self, pin: &[u8]) -> Result<(), HsmError> {
        if streebog256(pin) != self.pin_hash {
            return Err(HsmError::Auth);
        }
        self.tampered = false;
        self.failed_pins = 0;
        self.self_test()
    }

    pub fn is_tampered(&self) -> bool {
        self.tampered
    }

    /// Экспорт публичной части ключа (сертификаты). Секретные части не
    /// покидают HSM (§13.6 no raw private key export).
    pub fn export_public_key(&self, key: KeyHandle) -> Result<Vec<u8>, HsmError> {
        let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
        match (&slot.material, &slot.public) {
            (KeyMaterial::Hybrid(_), Some(pub_bytes)) => Ok(pub_bytes.clone()),
            _ => Err(HsmError::Policy),
        }
    }

    pub fn key_epoch(&self, key: KeyHandle) -> Result<u32, HsmError> {
        self.keys.get(&key).map(|s| s.epoch).ok_or(HsmError::KeyMissing)
    }

    /// Публичный ключ устройства как структура (для attestation/сертификатов).
    pub fn public_key_struct(&self, key: KeyHandle) -> Result<HybridPublicKey, HsmError> {
        let b = self.export_public_key(key)?;
        HybridPublicKey::from_bytes(&b).ok_or(HsmError::Policy)
    }

    // ---- платформенные расширения (не в trait; PKCS#11-эквиваленты
    // ---- C_DeriveKey/C_Decrypt, регистрация в КР-4) ----

    /// VKO ГОСТ Р 34.10-2012 (RFC 7836 §4.3.1) на секретном ключе HSM.
    /// Секрет не покидает HSM — возвращается только KEK (32 Б).
    pub fn vko_kek(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        peer_pub: &[u8; 64],
        ukm: u64,
    ) -> Result<[u8; 32], HsmError> {
        self.check_op()?;
        self.session(sid)?;
        let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
        match &slot.material {
            KeyMaterial::Hybrid(kp) => sakura_gost::gost3410::vko_kek_256(&kp.gost_priv, peer_pub, ukm)
                .map_err(|_| HsmError::Policy),
            _ => Err(HsmError::Policy),
        }
    }

    /// Декапсуляция ML-KEM-1024 на секретном ключе HSM (сеансовый ключ L4).
    pub fn kem_decapsulate(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        ct: &[u8],
        ss_out: &mut [u8],
    ) -> Result<usize, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        if ss_out.len() < 32 {
            return Err(HsmError::BufferTooSmall);
        }
        let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
        match &slot.material {
            KeyMaterial::Hybrid(kp) => {
                let ss = sakura_pq::mlkem1024_decapsulate(&kp.mlkem_dk, ct)
                    .map_err(|_| HsmError::InvalidArgument)?;
                ss_out[..32].copy_from_slice(&ss);
                Ok(32)
            }
            _ => Err(HsmError::Policy),
        }
    }

    /// Детерминированная подпись ГОСТ-части с фиксированным k — ТОЛЬКО для
    /// KAT-тестов (§23.8: production-k не детерминирован).
    #[cfg(test)]
    pub fn sign_deterministic_test(
        &mut self,
        key: KeyHandle,
        msg: &[u8],
        gost_k: &[u8; 32],
    ) -> Result<Vec<u8>, HsmError> {
        let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
        match &slot.material {
            KeyMaterial::Hybrid(kp) => {
                sakura_hybrid::sign::hybrid_sign_deterministic(kp, msg, gost_k)
                    .map_err(|_| HsmError::Io)
            }
            _ => Err(HsmError::Policy),
        }
    }

    fn check_op(&mut self) -> Result<(), HsmError> {
        if self.tampered {
            return Err(HsmError::Tamper);
        }
        if !self.self_test_passed {
            return Err(HsmError::SelfTestFailed);
        }
        let now = self.now_ms();
        if now.saturating_sub(self.ops_window_start_ms) >= 1000 {
            self.ops_window_start_ms = now;
            self.ops_in_window = 0;
        }
        self.ops_in_window += 1;
        if self.ops_in_window > self.ops_limit_per_s {
            return Err(HsmError::RateLimit);
        }
        Ok(())
    }

    fn session(&self, sid: SessionId) -> Result<(), HsmError> {
        match self.sessions.get(&sid) {
            Some(s) => {
                let age_s = self.now_ms().saturating_sub(s.opened_ms) / 1000;
                if age_s > self.max_session_s {
                    Err(HsmError::Session) // SESSION_EXPIRED (§13.8)
                } else {
                    Ok(())
                }
            }
            None => Err(HsmError::Session),
        }
    }

    /// Срок жизни сессии в секундах (для аудита/мониторинга).
    pub fn session_age_s(&self, sid: SessionId) -> Result<u64, HsmError> {
        let s = self.sessions.get(&sid).ok_or(HsmError::Session)?;
        Ok(self.now_ms().saturating_sub(s.opened_ms) / 1000)
    }

    #[cfg(test)]
    pub fn set_max_session_s(&mut self, v: u64) {
        self.max_session_s = v;
    }

    // ---- персистенция (эмуляция NVRAM HSM, §23.12 secure storage) ----

    /// Сохранить keystore в файл (MGM-шифрование под KEK от master-PIN).
    pub fn save_keystore(&self, path: &std::path::Path, master_pin: &[u8]) -> Result<(), HsmError> {
        let mut slots = Vec::new();
        for (h, s) in &self.keys {
            let secret: Vec<u8> = match &s.material {
                KeyMaterial::Hybrid(kp) => {
                    let mut v = Vec::with_capacity(32 + kp.mldsa_sk.len() + kp.mlkem_dk.len());
                    v.extend_from_slice(&kp.gost_priv);
                    v.extend_from_slice(&kp.mldsa_sk);
                    v.extend_from_slice(&kp.mlkem_dk);
                    v
                }
                KeyMaterial::Symmetric(b) => b.clone(),
                KeyMaterial::Zeroized => continue,
            };
            slots.push(Cbor::map(vec![
                (Cbor::text("handle"), Cbor::UInt(*h as u64)),
                (Cbor::text("class"), Cbor::UInt(s.class as u64)),
                (Cbor::text("key_type"), Cbor::UInt(s.key_type as u64)),
                (Cbor::text("epoch"), Cbor::UInt(s.epoch as u64)),
                (Cbor::text("secret"), Cbor::bytes(secret)),
                (
                    Cbor::text("public"),
                    s.public.clone().map(Cbor::bytes).unwrap_or(Cbor::Null),
                ),
            ]));
        }
        let doc = Cbor::map(vec![
            (Cbor::text("version"), Cbor::UInt(1)),
            (Cbor::text("next_handle"), Cbor::UInt(self.next_handle as u64)),
            (Cbor::text("slots"), Cbor::array(slots)),
        ]);
        let salt: Vec<u8> = vec![0x53, 0x41, 0x4B, 0x55]; // "SAKU"
        let kek = kek_from_pin(master_pin, &salt);
        let mut iv = [0u8; MGM_IV_LEN];
        sakura_common::rand::fill(&mut iv);
        iv[0] &= 0x7F;
        let ct = mgm_encrypt(&kek, &iv, b"keystore-v1", &doc.to_vec())
            .map_err(|_| HsmError::Io)?;
        let mut out = Vec::with_capacity(16 + ct.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        std::fs::write(path, &out).map_err(|_| HsmError::Io)
    }

    /// Загрузить keystore из файла.
    pub fn load_keystore(&mut self, path: &std::path::Path, master_pin: &[u8]) -> Result<(), HsmError> {
        let raw = std::fs::read(path).map_err(|_| HsmError::Io)?;
        if raw.len() < MGM_IV_LEN + sakura_hybrid::MGM_TAG_LEN {
            return Err(HsmError::Io);
        }
        let mut iv = [0u8; MGM_IV_LEN];
        iv.copy_from_slice(&raw[..MGM_IV_LEN]);
        let salt: Vec<u8> = vec![0x53, 0x41, 0x4B, 0x55];
        let kek = kek_from_pin(master_pin, &salt);
        let pt = mgm_decrypt(&kek, &iv, b"keystore-v1", &raw[MGM_IV_LEN..])
            .map_err(|_| HsmError::Auth)?;
        let doc = Cbor::from_slice(&pt).map_err(|_| HsmError::Io)?;
        let next_handle = doc.get("next_handle").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        let slots = doc.get("slots").and_then(|v| v.as_array()).ok_or(HsmError::Io)?;
        for slot in slots {
            let handle = slot.get("handle").and_then(|v| v.as_u64()).ok_or(HsmError::Io)? as u32;
            let class = slot.get("class").and_then(|v| v.as_u64()).ok_or(HsmError::Io)? as u8;
            let key_type = slot.get("key_type").and_then(|v| v.as_u64()).ok_or(HsmError::Io)? as u8;
            let epoch = slot.get("epoch").and_then(|v| v.as_u64()).ok_or(HsmError::Io)? as u32;
            let secret = slot.get("secret").and_then(|v| v.as_bytes()).ok_or(HsmError::Io)?.to_vec();
            let public = slot.get("public").and_then(|v| v.as_bytes()).map(|b| b.to_vec());
            let material = match key_type {
                crate::KEY_TYPE_HYBRID_SIGN => {
                    let pub_bytes = public.as_ref().ok_or(HsmError::Io)?;
                    let kp = keypair_from_secret(&secret, pub_bytes).ok_or(HsmError::Io)?;
                    KeyMaterial::Hybrid(Box::new(kp))
                }
                crate::KEY_TYPE_SYMMETRIC => KeyMaterial::Symmetric(secret),
                _ => return Err(HsmError::Io),
            };
            self.keys.insert(handle, KeySlot { class, key_type, epoch, material, public });
        }
        self.next_handle = next_handle;
        Ok(())
    }
}

fn kek_from_pin(pin: &[u8], salt: &[u8]) -> [u8; 32] {
    let h = hkdf_streebog256(&streebog256(pin), salt, b"SAKURA-KEYSTORE-KEK-V1", 32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h);
    k
}

fn keypair_from_secret(secret: &[u8], public: &[u8]) -> Option<HybridKeyPair> {
    const MLDSA_SK: usize = sakura_pq::MLDSA65_SK_LEN;
    const MLKEM_DK: usize = sakura_pq::MLKEM1024_DK_LEN;
    if secret.len() != 32 + MLDSA_SK + MLKEM_DK {
        return None;
    }
    let mut gost_priv = [0u8; 32];
    gost_priv.copy_from_slice(&secret[..32]);
    let mldsa_sk = secret[32..32 + MLDSA_SK].to_vec();
    let mlkem_dk = secret[32 + MLDSA_SK..].to_vec();
    // публичная часть восстанавливается из сохранённой (не секретна)
    let pk = HybridPublicKey::from_bytes(public)?;
    let gost_check = sakura_gost::gost3410::public_from_private(&gost_priv).ok()?;
    if gost_check != pk.gost {
        return None; // целостность keystore нарушена
    }
    Some(HybridKeyPair { gost_priv, mldsa_sk, mlkem_dk, public: pk })
}

impl HsmBackend for SoftHsm {
    fn open_session(&mut self, pin: &[u8]) -> Result<SessionId, HsmError> {
        if self.tampered {
            return Err(HsmError::Tamper);
        }
        let now = self.now_ms();
        if now.saturating_sub(self.sess_window_start_ms) >= 1000 {
            self.sess_window_start_ms = now;
            self.sess_in_window = 0;
        }
        self.sess_in_window += 1;
        if self.sess_in_window > self.sess_limit_per_s {
            return Err(HsmError::RateLimit);
        }
        if streebog256(pin) != self.pin_hash {
            self.failed_pins += 1;
            // §13.8 AUTH_FAILED → блокировка, аудит (3 неудачи — PIN-lock,
            // сброс только через ceremony_reset)
            return Err(HsmError::Auth);
        }
        if self.failed_pins >= 3 {
            return Err(HsmError::Auth); // PIN-lock до ceremony
        }
        self.failed_pins = 0;
        let sid = self.next_sid;
        self.next_sid += 1;
        self.sessions.insert(sid, Session { opened_ms: now });
        Ok(sid)
    }

    fn close_session(&mut self, sid: SessionId) -> Result<(), HsmError> {
        self.session(sid)?;
        self.sessions.remove(&sid);
        Ok(())
    }

    fn generate_key(
        &mut self,
        sid: SessionId,
        spec: &[u8],
        handle_out: &mut KeyHandle,
    ) -> Result<(), HsmError> {
        self.check_op()?;
        self.session(sid)?;
        if spec.len() < 2 {
            return Err(HsmError::InvalidArgument);
        }
        let key_type = spec[0];
        let class = spec[1];
        let handle = self.next_handle;
        let slot = match key_type {
            crate::KEY_TYPE_HYBRID_SIGN => {
                let kp = HybridKeyPair::generate().map_err(|_| HsmError::Io)?;
                let public = Some(kp.public.to_bytes());
                KeySlot { class, key_type, epoch: 1, material: KeyMaterial::Hybrid(Box::new(kp)), public }
            }
            crate::KEY_TYPE_SYMMETRIC => {
                let mut secret = vec![0u8; 32];
                sakura_common::rand::fill(&mut secret);
                KeySlot { class, key_type, epoch: 1, material: KeyMaterial::Symmetric(secret), public: None }
            }
            _ => return Err(HsmError::InvalidArgument),
        };
        self.keys.insert(handle, slot);
        self.next_handle += 1;
        *handle_out = handle;
        Ok(())
    }

    fn sign(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        data: &[u8],
        sig_out: &mut [u8],
    ) -> Result<usize, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
        match &slot.material {
            KeyMaterial::Hybrid(kp) => {
                if sig_out.len() < HYBRID_SIG_SIZE {
                    return Err(HsmError::BufferTooSmall); // BC-18
                }
                let sig = sakura_hybrid::hybrid_sign(kp, data).map_err(|_| HsmError::Io)?;
                sig_out[..sig.len()].copy_from_slice(&sig);
                Ok(sig.len())
            }
            _ => Err(HsmError::Policy),
        }
    }

    fn verify(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
        match (&slot.material, &slot.public) {
            (KeyMaterial::Hybrid(_), Some(pub_bytes)) => {
                let pk = HybridPublicKey::from_bytes(pub_bytes).ok_or(HsmError::Policy)?;
                Ok(sakura_hybrid::hybrid_verify(&pk, data, sig))
            }
            _ => Err(HsmError::Policy),
        }
    }

    fn encrypt(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        plaintext: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        if ct_out.len() < plaintext.len() + MGM_OVERHEAD {
            return Err(HsmError::BufferTooSmall);
        }
        let mut key32 = [0u8; 32];
        {
            let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
            match &slot.material {
                KeyMaterial::Symmetric(s) if s.len() == 32 => key32.copy_from_slice(s),
                _ => return Err(HsmError::Policy),
            }
        }
        let mut iv = [0u8; MGM_IV_LEN];
        sakura_common::rand::fill(&mut iv);
        iv[0] &= 0x7F; // MGM: старший бит nonce = 0
        let ct = mgm_encrypt(&key32, &iv, b"HSM-STORAGE-V1", plaintext).map_err(|_| HsmError::Io)?;
        ct_out[..MGM_IV_LEN].copy_from_slice(&iv);
        ct_out[MGM_IV_LEN..MGM_IV_LEN + ct.len()].copy_from_slice(&ct);
        key32.iter_mut().for_each(|b| *b = 0); // обнуление секретного буфера (BC-18)
        Ok(MGM_IV_LEN + ct.len())
    }

    fn decrypt(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        ciphertext: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        if ciphertext.len() < MGM_OVERHEAD {
            return Err(HsmError::InvalidArgument);
        }
        let mut key32 = [0u8; 32];
        {
            let slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
            match &slot.material {
                KeyMaterial::Symmetric(s) if s.len() == 32 => key32.copy_from_slice(s),
                _ => return Err(HsmError::Policy),
            }
        }
        let mut iv = [0u8; MGM_IV_LEN];
        iv.copy_from_slice(&ciphertext[..MGM_IV_LEN]);
        let pt = mgm_decrypt(&key32, &iv, b"HSM-STORAGE-V1", &ciphertext[MGM_IV_LEN..])
            .map_err(|_| HsmError::InvalidArgument)?;
        if pt_out.len() < pt.len() {
            key32.iter_mut().for_each(|b| *b = 0);
            return Err(HsmError::BufferTooSmall);
        }
        pt_out[..pt.len()].copy_from_slice(&pt);
        key32.iter_mut().for_each(|b| *b = 0);
        Ok(pt.len())
    }

    fn wrap_key(
        &mut self,
        sid: SessionId,
        kek: KeyHandle,
        key: KeyHandle,
        wrapped_out: &mut [u8],
    ) -> Result<usize, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        let (kek_secret, target) = {
            let kek_slot = self.keys.get(&kek).ok_or(HsmError::KeyMissing)?;
            let kek_secret = match &kek_slot.material {
                KeyMaterial::Symmetric(s) if s.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(s);
                    a
                }
                _ => return Err(HsmError::Policy),
            };
            let t_slot = self.keys.get(&key).ok_or(HsmError::KeyMissing)?;
            // wrap разрешён только для симметрических ключей (L5 storage);
            // гибридные подписные ключи не покидают HSM ни в каком виде
            let target = match &t_slot.material {
                KeyMaterial::Symmetric(s) => s.clone(),
                _ => return Err(HsmError::Policy),
            };
            (kek_secret, target)
        };
        let mut seed = [0u8; 8];
        sakura_common::rand::fill(&mut seed);
        let wrapped = sakura_gost::gost28147::wrap_key(&kek_secret, &target, &seed)
            .map_err(|_| HsmError::Io)?;
        if wrapped_out.len() < wrapped.len() {
            return Err(HsmError::BufferTooSmall);
        }
        wrapped_out[..wrapped.len()].copy_from_slice(&wrapped);
        Ok(wrapped.len())
    }

    fn unwrap_key(
        &mut self,
        sid: SessionId,
        kek: KeyHandle,
        wrapped: &[u8],
        handle_out: &mut KeyHandle,
    ) -> Result<(), HsmError> {
        self.check_op()?;
        self.session(sid)?;
        let mut kek_secret = [0u8; 32];
        {
            let kek_slot = self.keys.get(&kek).ok_or(HsmError::KeyMissing)?;
            match &kek_slot.material {
                KeyMaterial::Symmetric(s) if s.len() == 32 => kek_secret.copy_from_slice(s),
                _ => return Err(HsmError::Policy),
            }
        }
        let secret = sakura_gost::gost28147::unwrap_key(&kek_secret, wrapped)
            .map_err(|_| HsmError::InvalidArgument)?;
        let handle = self.next_handle;
        self.keys.insert(
            handle,
            KeySlot {
                class: crate::KEY_CLASS_STORAGE,
                key_type: crate::KEY_TYPE_SYMMETRIC,
                epoch: 1,
                material: KeyMaterial::Symmetric(secret),
                public: None,
            },
        );
        self.next_handle += 1;
        *handle_out = handle;
        Ok(())
    }

    fn attest(
        &mut self,
        sid: SessionId,
        nonce: &[u8],
        report_out: &mut [u8],
    ) -> Result<usize, HsmError> {
        self.check_op()?;
        self.session(sid)?;
        if nonce.len() < 16 {
            return Err(HsmError::InvalidArgument); // §13.19.2: nonce ≥16 Б
        }
        let status = if self.tampered {
            "TAMPER"
        } else if self.self_test_passed {
            "OK"
        } else {
            "SELF_TEST_FAILED"
        };
        let report = Cbor::map(vec![
            (Cbor::text("fw"), Cbor::text(SOFT_HSM_FW)),
            (Cbor::text("hsm_status"), Cbor::text(status)),
            (Cbor::text("nonce"), Cbor::bytes(nonce.to_vec())),
            (Cbor::text("self_test"), Cbor::text(if self.self_test_passed { "PASS" } else { "FAIL" })),
            (Cbor::text("tamper"), Cbor::Bool(self.tampered)),
            (Cbor::text("uptime_s"), Cbor::UInt(self.now_ms() / 1000)),
            (Cbor::text("class"), Cbor::text("KS3-emulation/SIL")),
        ]);
        let enc = report.to_vec();
        if report_out.len() < enc.len() {
            return Err(HsmError::BufferTooSmall);
        }
        report_out[..enc.len()].copy_from_slice(&enc);
        Ok(enc.len())
    }

    fn zeroize(&mut self, sid: SessionId, key: KeyHandle) -> Result<(), HsmError> {
        self.check_op()?;
        self.session(sid)?;
        let slot = self.keys.get_mut(&key).ok_or(HsmError::KeyMissing)?;
        slot.material = KeyMaterial::Zeroized;
        slot.public = None;
        slot.epoch = slot.epoch.wrapping_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hsm() -> (SoftHsm, SessionId) {
        let mut h = SoftHsm::new(b"master-pin").unwrap();
        let sid = h.open_session(b"master-pin").unwrap();
        (h, sid)
    }

    #[test]
    fn session_auth() {
        let mut h = SoftHsm::new(b"master-pin").unwrap();
        assert_eq!(h.open_session(b"wrong-pin"), Err(HsmError::Auth));
        let sid = h.open_session(b"master-pin").unwrap();
        // операции без сессии невозможны
        let mut h2 = 0u32;
        assert_eq!(
            h.generate_key(9999, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_STORAGE], &mut h2),
            Err(HsmError::Session)
        );
        h.close_session(sid).unwrap();
        assert_eq!(h.close_session(sid), Err(HsmError::Session));
    }

    #[test]
    fn sign_verify_flow_and_buffer_too_small() {
        let (mut h, sid) = hsm();
        let mut key = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_HYBRID_SIGN, crate::KEY_CLASS_DEVICE_IDENTITY], &mut key)
            .unwrap();
        let msg = b"attestation payload";
        // маленький буфер → BufferTooSmall (BC-18)
        let mut small = [0u8; 96];
        assert_eq!(h.sign(sid, key, msg, &mut small), Err(HsmError::BufferTooSmall));
        // фиксированные 96 Б запрещены (BC-19): нужна переменная длина 3373
        let mut sig = [0u8; HYBRID_SIG_SIZE];
        let n = h.sign(sid, key, msg, &mut sig).unwrap();
        assert_eq!(n, HYBRID_SIG_SIZE);
        assert!(h.verify(sid, key, msg, &sig).unwrap());
        sig[0] ^= 1;
        assert!(!h.verify(sid, key, msg, &sig).unwrap());
        // публичная часть экспортируется, секретная — нет (нет такого API)
        let pubk = h.export_public_key(key).unwrap();
        assert_eq!(pubk.len(), sakura_hybrid::HYBRID_PK_LEN + sakura_hybrid::MLKEM_EK_LEN);
    }

    #[test]
    fn encrypt_decrypt_symmetric() {
        let (mut h, sid) = hsm();
        let mut key = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_STORAGE], &mut key)
            .unwrap();
        let pt = b"storage encryption payload";
        let mut ct = vec![0u8; pt.len() + MGM_OVERHEAD];
        let n = h.encrypt(sid, key, pt, &mut ct).unwrap();
        assert_eq!(n, pt.len() + MGM_OVERHEAD);
        let mut out = vec![0u8; pt.len()];
        let m = h.decrypt(sid, key, &ct[..n], &mut out).unwrap();
        assert_eq!(m, pt.len());
        assert_eq!(&out[..m], pt);
        // маленький буфер
        let mut tiny = [0u8; 4];
        assert_eq!(h.encrypt(sid, key, pt, &mut tiny), Err(HsmError::BufferTooSmall));
    }

    #[test]
    fn wrap_unwrap_flow() {
        let (mut h, sid) = hsm();
        let mut kek = 0u32;
        let mut storage = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_KEK], &mut kek).unwrap();
        h.generate_key(sid, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_STORAGE], &mut storage)
            .unwrap();
        let mut wrapped = [0u8; 128];
        let n = h.wrap_key(sid, kek, storage, &mut wrapped).unwrap();
        assert!(n > 0 && n <= 128);
        let mut restored = 0u32;
        h.unwrap_key(sid, kek, &wrapped[..n], &mut restored).unwrap();
        assert_ne!(restored, storage);
        // roundtrip данных через encrypt обоими ключами
        let pt = b"same-secret-check";
        let mut ct1 = vec![0u8; pt.len() + MGM_OVERHEAD];
        let l1 = h.encrypt(sid, storage, pt, &mut ct1).unwrap();
        let mut out = vec![0u8; pt.len()];
        h.decrypt(sid, restored, &ct1[..l1], &mut out).unwrap();
        assert_eq!(&out, pt, "unwrapped key == original");
        // wrap гибридного ключа запрещён (no key export)
        let mut sign_key = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_HYBRID_SIGN, crate::KEY_CLASS_DEVICE_IDENTITY], &mut sign_key)
            .unwrap();
        assert_eq!(h.wrap_key(sid, kek, sign_key, &mut wrapped), Err(HsmError::Policy));
    }

    #[test]
    fn tamper_and_zeroize() {
        let (mut h, sid) = hsm();
        let mut key = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_HYBRID_SIGN, crate::KEY_CLASS_DEVICE_IDENTITY], &mut key)
            .unwrap();
        h.zeroize(sid, key).unwrap();
        let mut sig = [0u8; HYBRID_SIG_SIZE];
        assert_eq!(h.sign(sid, key, b"x", &mut sig), Err(HsmError::Policy));
        // tamper: все операции блокируются, сессии закрыты
        let mut key2 = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_STORAGE], &mut key2)
            .unwrap();
        h.trigger_tamper();
        assert_eq!(h.open_session(b"master-pin"), Err(HsmError::Tamper));
        let sid2 = {
            h.tampered = false; // имитация ceremony-доступа для проверки ops
            h.open_session(b"master-pin").unwrap()
        };
        h.tampered = true;
        let mut out = [0u8; 64];
        assert_eq!(h.encrypt(sid2, key2, b"x", &mut out), Err(HsmError::Tamper));
        // ceremony-сброс с неверным PIN → Auth
        assert_eq!(h.ceremony_reset(b"bad"), Err(HsmError::Auth));
        h.ceremony_reset(b"master-pin").unwrap();
        assert!(!h.is_tampered());
    }

    #[test]
    fn attestation_report() {
        let (mut h, sid) = hsm();
        let mut nonce = [0u8; 32];
        sakura_common::rand::fill(&mut nonce);
        let mut small = [0u8; 4];
        assert_eq!(h.attest(sid, &nonce, &mut small), Err(HsmError::BufferTooSmall));
        let mut buf = [0u8; 512];
        let n = h.attest(sid, &nonce, &mut buf).unwrap();
        let rep = Cbor::from_slice(&buf[..n]).unwrap();
        assert_eq!(rep.get("hsm_status").unwrap().as_text(), Some("OK"));
        assert_eq!(rep.get("nonce").unwrap().as_bytes().unwrap(), &nonce[..]);
        // короткий nonce → InvalidArgument
        assert_eq!(h.attest(sid, &[1u8; 8], &mut buf), Err(HsmError::InvalidArgument));
    }

    #[test]
    fn rate_limiting() {
        // лимиты задаются ДО открытия сессий (окно — 1 с)
        let mut h = SoftHsm::new(b"master-pin").unwrap();
        h.set_rate_limits(3, 2);
        let sid = h.open_session(b"master-pin").unwrap(); // sess 1
        h.open_session(b"master-pin").unwrap(); // sess 2
        assert_eq!(h.open_session(b"master-pin"), Err(HsmError::RateLimit));
        let mut key = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_STORAGE], &mut key)
            .unwrap(); // op1
        let mut out = [0u8; 64];
        h.encrypt(sid, key, b"1", &mut out).unwrap(); // op2
        h.encrypt(sid, key, b"2", &mut out).unwrap(); // op3
        assert_eq!(h.encrypt(sid, key, b"3", &mut out), Err(HsmError::RateLimit));
    }

    #[test]
    fn session_expiry() {
        let mut h = SoftHsm::new(b"master-pin").unwrap();
        h.set_max_session_s(0); // сессия истекает немедленно
        let sid = h.open_session(b"master-pin").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut key = 0u32;
        assert_eq!(
            h.generate_key(sid, &[crate::KEY_TYPE_SYMMETRIC, crate::KEY_CLASS_STORAGE], &mut key),
            Err(HsmError::Session)
        );
        assert!(h.session_age_s(sid).unwrap() >= 1);
    }

    #[test]
    fn keystore_persistence() {
        let dir = std::env::temp_dir().join(format!("softhsm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.bin");
        let (mut h, sid) = hsm();
        let mut key = 0u32;
        h.generate_key(sid, &[crate::KEY_TYPE_HYBRID_SIGN, crate::KEY_CLASS_DEVICE_IDENTITY], &mut key)
            .unwrap();
        let pub_before = h.export_public_key(key).unwrap();
        let msg = b"persist-check";
        let mut sig = [0u8; HYBRID_SIG_SIZE];
        h.sign(sid, key, msg, &mut sig).unwrap();
        h.save_keystore(&path, b"master-pin").unwrap();

        let mut h2 = SoftHsm::new(b"master-pin").unwrap();
        h2.load_keystore(&path, b"master-pin").unwrap();
        let sid2 = h2.open_session(b"master-pin").unwrap();
        // подпись прежним ключом проверяется
        assert!(h2.verify(sid2, key, msg, &sig).unwrap());
        assert_eq!(h2.export_public_key(key).unwrap(), pub_before);
        // неверный PIN → отказ расшифрования keystore
        let mut h3 = SoftHsm::new(b"master-pin").unwrap();
        assert!(h3.load_keystore(&path, b"wrong").is_err());
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
