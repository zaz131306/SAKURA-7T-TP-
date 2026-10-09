//! HSM-agent (fw/hsm-agent) — slice-based API по BC-18 / HSM-API-001:
//!
//! ```text
//! MUST: в boot-critical и control-plane путях не используется динамическая память.
//! MUST: API возвращает данные в буферы вызывающей стороны.
//! MUST: при недостаточном размере буфера возвращается BufferTooSmall.
//! MUST: временные буферы с секретными данными обнуляются после использования.
//! MUST: HsmError::Ok удалён; успех = Ok(()).
//! ```
//!
//! Трейт [`HsmBackend`] — точная кода спецификации ТП §22.5.1 (no_std, без
//! аллокаций). Реализация [`soft::SoftHsm`] (feature `std`) — программная
//! эмуляция HSM-контура для SIL/HIL; в production — сертифицированный HSM
//! класса КС3 (BC-16, КР-4: модель фиксируется после vendor confirmation).
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
pub mod soft;

pub type SessionId = u32;
pub type KeyHandle = u32;

/// Коды ошибок HSM (§13.6, §22.5). `HsmError::Ok` отсутствует (C-03):
/// успех = `Ok(())`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsmError {
    Session,
    Auth,
    Tamper,
    RateLimit,
    KeyMissing,
    Policy,
    SelfTestFailed,
    Io,
    BufferTooSmall,
    InvalidArgument,
}

/// Имена для журнала/API (§13.6).
impl HsmError {
    pub fn as_str(self) -> &'static str {
        match self {
            HsmError::Session => "HSM_SESSION",
            HsmError::Auth => "HSM_AUTH",
            HsmError::Tamper => "HSM_TAMPER",
            HsmError::RateLimit => "HSM_RATE_LIMIT",
            HsmError::KeyMissing => "HSM_KEY_MISSING",
            HsmError::Policy => "HSM_POLICY",
            HsmError::SelfTestFailed => "HSM_SELF_TEST_FAILED",
            HsmError::Io => "HSM_IO",
            HsmError::BufferTooSmall => "HSM_BUFFER_TOO_SMALL",
            HsmError::InvalidArgument => "HSM_INVALID_ARGUMENT",
        }
    }
}

// ---- Классы ключей (иерархия §23.6, L0–L9) ----
pub const KEY_CLASS_DEVICE_IDENTITY: u8 = 2; // L2
pub const KEY_CLASS_SESSION: u8 = 4; // L4
pub const KEY_CLASS_STORAGE: u8 = 5; // L5
pub const KEY_CLASS_FIRMWARE_SIGNING: u8 = 7; // L7 (в CA-контуре)
pub const KEY_CLASS_KEK: u8 = 8; // wrap-KEK домена

/// Типы ключей для generate_key (spec-байт 0).
pub const KEY_TYPE_HYBRID_SIGN: u8 = 0x01; // ГОСТ 34.10 + ML-DSA-65 + ML-KEM-1024
pub const KEY_TYPE_SYMMETRIC: u8 = 0x02; // 256-бит симметричный (KEK/storage)

/// Slice-based трейт HSM (§22.5.1, BC-18). Все выходные данные —
/// в буферы вызывающей стороны; недостаточный размер → BufferTooSmall.
pub trait HsmBackend {
    fn open_session(&mut self, pin: &[u8]) -> Result<SessionId, HsmError>;
    fn close_session(&mut self, sid: SessionId) -> Result<(), HsmError>;

    fn generate_key(
        &mut self,
        sid: SessionId,
        spec: &[u8],
        handle_out: &mut KeyHandle,
    ) -> Result<(), HsmError>;

    /// Подпись: возвращает длину подписи, записанной в sig_out.
    fn sign(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        data: &[u8],
        sig_out: &mut [u8],
    ) -> Result<usize, HsmError>;

    fn verify(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, HsmError>;

    fn encrypt(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        plaintext: &[u8],
        ct_out: &mut [u8],
    ) -> Result<usize, HsmError>;

    fn decrypt(
        &mut self,
        sid: SessionId,
        key: KeyHandle,
        ciphertext: &[u8],
        pt_out: &mut [u8],
    ) -> Result<usize, HsmError>;

    fn wrap_key(
        &mut self,
        sid: SessionId,
        kek: KeyHandle,
        key: KeyHandle,
        wrapped_out: &mut [u8],
    ) -> Result<usize, HsmError>;

    fn unwrap_key(
        &mut self,
        sid: SessionId,
        kek: KeyHandle,
        wrapped: &[u8],
        handle_out: &mut KeyHandle,
    ) -> Result<(), HsmError>;

    /// Attestation состояния HSM (nonce обязателен, §13.17: nonce binding);
    /// возвращает длину отчёта в report_out.
    fn attest(
        &mut self,
        sid: SessionId,
        nonce: &[u8],
        report_out: &mut [u8],
    ) -> Result<usize, HsmError>;

    fn zeroize(&mut self, sid: SessionId, key: KeyHandle) -> Result<(), HsmError>;
}
