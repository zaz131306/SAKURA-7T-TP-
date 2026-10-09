//! Общие коды ошибок ICD-1 §13.8 (+ NPP §13.3, severity и реакция).
//! Каждый ответ API-1 содержит `result` — "OK" или имя кода из данной таблицы.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
    /// CRITICAL для control-трафика, WARNING для non-control (NPP_FEC_UNCORRECTABLE).
    CriticalControlWarning,
    Critical,
    Fatal,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
            Severity::CriticalControlWarning => "CRITICAL/WARNING",
            Severity::Critical => "CRITICAL",
            Severity::Fatal => "FATAL",
        }
    }
}

/// Таблица ICD-1 §13.8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    Ok = 0x0000,
    SessionExpired = 0x0001,
    AuthFailed = 0x0002,
    TamperDetected = 0x0003,
    RateLimit = 0x0004,
    KeyMissing = 0x0005,
    PolicyViolation = 0x0006,
    SelfTestFailed = 0x0007,
    NetworkPartition = 0x0008,
    TimeSyncLost = 0x0009,
    QuorumLost = 0x000A,
    ModelAttestationFailed = 0x000B,
    RollbackDetected = 0x000C,
    SecureBootFailed = 0x000D,
    ZeroizationTriggered = 0x000E,
    UpdateRejected = 0x000F,
    NppPaddingInvalid = 0x0010,
    NppFecUncorrectable = 0x0011,
    NppFrameTooLong = 0x0012,
    // --- NPP-протокольные (§13.3) ---
    InvalidFrame = 0x0101,
    UnsupportedVersion = 0x0102,
    NppAuthFailed = 0x0103,
    ReplayDetected = 0x0104,
    SeqOutOfWindow = 0x0105,
    FragmentTimeout = 0x0106,
    ResourceExhausted = 0x0107,
    NppPolicyViolation = 0x0108,
    EthicsRejected = 0x0109,
    NppSessionExpired = 0x010A,
    ChannelBindingMismatch = 0x010B,
}

impl ErrorCode {
    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        use ErrorCode::*;
        Some(match v {
            0x0000 => Ok,
            0x0001 => SessionExpired,
            0x0002 => AuthFailed,
            0x0003 => TamperDetected,
            0x0004 => RateLimit,
            0x0005 => KeyMissing,
            0x0006 => PolicyViolation,
            0x0007 => SelfTestFailed,
            0x0008 => NetworkPartition,
            0x0009 => TimeSyncLost,
            0x000A => QuorumLost,
            0x000B => ModelAttestationFailed,
            0x000C => RollbackDetected,
            0x000D => SecureBootFailed,
            0x000E => ZeroizationTriggered,
            0x000F => UpdateRejected,
            0x0010 => NppPaddingInvalid,
            0x0011 => NppFecUncorrectable,
            0x0012 => NppFrameTooLong,
            0x0101 => InvalidFrame,
            0x0102 => UnsupportedVersion,
            0x0103 => NppAuthFailed,
            0x0104 => ReplayDetected,
            0x0105 => SeqOutOfWindow,
            0x0106 => FragmentTimeout,
            0x0107 => ResourceExhausted,
            0x0108 => NppPolicyViolation,
            0x0109 => EthicsRejected,
            0x010A => NppSessionExpired,
            0x010B => ChannelBindingMismatch,
            _ => return None,
        })
    }

    /// Строковое имя для поля `result` API-1 (§13.19.3).
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            Ok => "OK",
            SessionExpired => "SESSION_EXPIRED",
            AuthFailed => "AUTH_FAILED",
            TamperDetected => "TAMPER_DETECTED",
            RateLimit => "RATE_LIMIT",
            KeyMissing => "KEY_MISSING",
            PolicyViolation => "POLICY_VIOLATION",
            SelfTestFailed => "SELF_TEST_FAILED",
            NetworkPartition => "NETWORK_PARTITION",
            TimeSyncLost => "TIME_SYNC_LOST",
            QuorumLost => "QUORUM_LOST",
            ModelAttestationFailed => "MODEL_ATTESTATION_FAILED",
            RollbackDetected => "ROLLBACK_DETECTED",
            SecureBootFailed => "SECURE_BOOT_FAILED",
            ZeroizationTriggered => "ZEROIZATION_TRIGGERED",
            UpdateRejected => "UPDATE_REJECTED",
            NppPaddingInvalid => "NPP_PADDING_INVALID",
            NppFecUncorrectable => "NPP_FEC_UNCORRECTABLE",
            NppFrameTooLong => "NPP_FRAME_TOO_LONG",
            InvalidFrame => "INVALID_FRAME",
            UnsupportedVersion => "UNSUPPORTED_VERSION",
            NppAuthFailed => "NPP_AUTH_FAILED",
            ReplayDetected => "REPLAY_DETECTED",
            SeqOutOfWindow => "SEQ_OUT_OF_WINDOW",
            FragmentTimeout => "FRAGMENT_TIMEOUT",
            ResourceExhausted => "RESOURCE_EXHAUSTED",
            NppPolicyViolation => "NPP_POLICY_VIOLATION",
            EthicsRejected => "ETHICS_REJECTED",
            NppSessionExpired => "NPP_SESSION_EXPIRED",
            ChannelBindingMismatch => "CHANNEL_BINDING_MISMATCH",
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        (0x0000u16..=0x0200)
            .filter_map(ErrorCode::from_u16)
            .find(|c| c.as_str() == s)
    }

    pub fn severity(self) -> Severity {
        use ErrorCode::*;
        use Severity::*;
        match self {
            Ok => Info,
            SessionExpired | RateLimit | NetworkPartition | TimeSyncLost => Warning,
            AuthFailed | KeyMissing | PolicyViolation | ModelAttestationFailed | UpdateRejected
            | NppPaddingInvalid | NppFrameTooLong => Error,
            TamperDetected | QuorumLost | RollbackDetected | ZeroizationTriggered => Critical,
            SelfTestFailed | SecureBootFailed => Fatal,
            NppFecUncorrectable => CriticalControlWarning,
            InvalidFrame | UnsupportedVersion | NppAuthFailed | ReplayDetected
            | SeqOutOfWindow | FragmentTimeout | ResourceExhausted | NppPolicyViolation
            | EthicsRejected | NppSessionExpired | ChannelBindingMismatch => Error,
        }
    }

    /// Рекомендуемая реакция (§13.8).
    pub fn reaction(self) -> &'static str {
        use ErrorCode::*;
        match self {
            Ok => "—",
            SessionExpired => "Переоткрытие сессии",
            AuthFailed => "Блокировка, аудит",
            TamperDetected => "Lockdown, zeroization",
            RateLimit => "Задержка, retry",
            KeyMissing => "Отказ операции",
            PolicyViolation => "Отказ, аудит",
            SelfTestFailed => "Lockdown",
            NetworkPartition => "Local autonomy",
            TimeSyncLost => "Holdover",
            QuorumLost => "ISOLATED",
            ModelAttestationFailed => "Отказ загрузки модели",
            RollbackDetected => "Lockdown, аудит",
            SecureBootFailed => "Recovery mode",
            ZeroizationTriggered => "Аудит, ceremony",
            UpdateRejected => "Откат, аудит",
            NppPaddingInvalid => "Отказ кадра",
            NppFecUncorrectable => "Отказ/деградация",
            NppFrameTooLong => "Отказ кадра",
            InvalidFrame | UnsupportedVersion => "Отказ кадра, ERROR-ответ",
            NppAuthFailed => "Разрыв сессии, аудит",
            ReplayDetected => "Отклонение, аудит",
            SeqOutOfWindow => "Отклонение, аудит",
            FragmentTimeout => "Сброс сборки",
            ResourceExhausted => "Backpressure",
            NppPolicyViolation => "Отклонение, аудит",
            EthicsRejected => "Отклонение плана, аудит",
            NppSessionExpired => "Перезаключение сессии",
            ChannelBindingMismatch => "Разрыв сессии, аудит",
        }
    }

    /// CRITICAL/FATAL не подавляются клиентом — дублируются в SIEM (§13.19.3).
    pub fn must_duplicate_to_siem(self) -> bool {
        matches!(
            self.severity(),
            Severity::Critical | Severity::Fatal | Severity::CriticalControlWarning
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}(0x{:04X})", self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_icd_13_8() {
        assert_eq!(ErrorCode::Ok.code(), 0x0000);
        assert_eq!(ErrorCode::SessionExpired.code(), 0x0001);
        assert_eq!(ErrorCode::TamperDetected.code(), 0x0003);
        assert_eq!(ErrorCode::QuorumLost.code(), 0x000A);
        assert_eq!(ErrorCode::RollbackDetected.code(), 0x000C);
        assert_eq!(ErrorCode::SecureBootFailed.code(), 0x000D);
        assert_eq!(ErrorCode::UpdateRejected.code(), 0x000F);
        assert_eq!(ErrorCode::NppPaddingInvalid.code(), 0x0010);
        assert_eq!(ErrorCode::NppFecUncorrectable.code(), 0x0011);
        assert_eq!(ErrorCode::NppFrameTooLong.code(), 0x0012);
    }

    #[test]
    fn roundtrip_and_names() {
        for c in 0x0000u16..=0x0012 {
            let e = ErrorCode::from_u16(c).unwrap();
            assert_eq!(e.code(), c);
            assert_eq!(ErrorCode::from_str_name(e.as_str()), Some(e));
        }
        assert_eq!(ErrorCode::from_u16(0x00FF), None);
        assert!(ErrorCode::TamperDetected.must_duplicate_to_siem());
        assert!(!ErrorCode::RateLimit.must_duplicate_to_siem());
        assert_eq!(ErrorCode::NppFecUncorrectable.severity(), Severity::CriticalControlWarning);
    }
}
