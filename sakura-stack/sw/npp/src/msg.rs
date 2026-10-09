//! Типы сообщений NPP и коды ошибок (§13.3).
//! Поле Type кадра — 1 байт: используется младший байт кода из таблицы
//! (решение ICD: старший байт кодов §13.3 всегда 0x00).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Hello = 0x01,
    AuthChallenge = 0x02,
    AuthResponse = 0x03,
    SessionEstablish = 0x04,
    SessionConfirm = 0x05,
    Heartbeat = 0x10,
    HeartbeatAck = 0x11,
    PlanRequest = 0x20,
    PlanResponse = 0x21,
    PlanAck = 0x22,
    PlanReject = 0x23,
    SensorSummary = 0x30,
    OperatorState = 0x31,
    ControlCommand = 0x40,
    ControlAck = 0x41,
    Error = 0x50,
    Status = 0x51,
    AuditExportRequest = 0x60,
    AuditExportChunk = 0x61,
    // --- аддендум ICD-1: внутренние плоскости платформы ---
    ConsensusMsg = 0x70,
    CrdtSync = 0x71,
    ControlApi = 0x72,
    TimeSync = 0x73,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        use MsgType::*;
        Some(match v {
            0x01 => Hello,
            0x02 => AuthChallenge,
            0x03 => AuthResponse,
            0x04 => SessionEstablish,
            0x05 => SessionConfirm,
            0x10 => Heartbeat,
            0x11 => HeartbeatAck,
            0x20 => PlanRequest,
            0x21 => PlanResponse,
            0x22 => PlanAck,
            0x23 => PlanReject,
            0x30 => SensorSummary,
            0x31 => OperatorState,
            0x40 => ControlCommand,
            0x41 => ControlAck,
            0x50 => Error,
            0x51 => Status,
            0x60 => AuditExportRequest,
            0x61 => AuditExportChunk,
            0x70 => ConsensusMsg,
            0x71 => CrdtSync,
            0x72 => ControlApi,
            0x73 => TimeSync,
            _ => return None,
        })
    }

    /// Control-трафик: FEC_UNCORRECTABLE → CRITICAL (иначе WARNING), §13.8.
    pub fn is_control(self) -> bool {
        matches!(
            self,
            MsgType::ControlCommand
                | MsgType::ControlAck
                | MsgType::PlanRequest
                | MsgType::PlanResponse
                | MsgType::PlanAck
                | MsgType::PlanReject
        )
    }
}

/// Коды ошибок NPP (§13.3) — передаются в payload ERROR-кадра (2 Б, BE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NppErrCode {
    InvalidFrame = 0x0001,
    UnsupportedVersion = 0x0002,
    AuthFailed = 0x0003,
    ReplayDetected = 0x0004,
    SeqOutOfWindow = 0x0005,
    FragmentTimeout = 0x0006,
    ResourceExhausted = 0x0007,
    PolicyViolation = 0x0008,
    EthicsRejected = 0x0009,
    SessionExpired = 0x000A,
    ChannelBindingMismatch = 0x000B,
}

impl NppErrCode {
    pub fn code(self) -> u16 {
        self as u16
    }
    /// Маппинг в общие коды §13.8 для API-ответов.
    pub fn to_common(self) -> sakura_common::ErrorCode {
        use sakura_common::ErrorCode::*;
        match self {
            NppErrCode::InvalidFrame => InvalidFrame,
            NppErrCode::UnsupportedVersion => UnsupportedVersion,
            NppErrCode::AuthFailed => NppAuthFailed,
            NppErrCode::ReplayDetected => ReplayDetected,
            NppErrCode::SeqOutOfWindow => SeqOutOfWindow,
            NppErrCode::FragmentTimeout => FragmentTimeout,
            NppErrCode::ResourceExhausted => ResourceExhausted,
            NppErrCode::PolicyViolation => NppPolicyViolation,
            NppErrCode::EthicsRejected => EthicsRejected,
            NppErrCode::SessionExpired => NppSessionExpired,
            NppErrCode::ChannelBindingMismatch => ChannelBindingMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_codes_match_spec() {
        assert_eq!(MsgType::Hello as u8, 0x01);
        assert_eq!(MsgType::SessionConfirm as u8, 0x05);
        assert_eq!(MsgType::Heartbeat as u8, 0x10);
        assert_eq!(MsgType::PlanRequest as u8, 0x20);
        assert_eq!(MsgType::ControlCommand as u8, 0x40);
        assert_eq!(MsgType::Error as u8, 0x50);
        assert_eq!(MsgType::AuditExportChunk as u8, 0x61);
        assert_eq!(MsgType::from_u8(0x40), Some(MsgType::ControlCommand));
        assert_eq!(MsgType::from_u8(0x77), None);
    }

    #[test]
    fn err_codes_match_spec() {
        assert_eq!(NppErrCode::InvalidFrame.code(), 0x0001);
        assert_eq!(NppErrCode::ReplayDetected.code(), 0x0004);
        assert_eq!(NppErrCode::ChannelBindingMismatch.code(), 0x000B);
        assert_eq!(
            NppErrCode::ReplayDetected.to_common(),
            sakura_common::ErrorCode::ReplayDetected
        );
    }

    #[test]
    fn control_classification() {
        assert!(MsgType::ControlCommand.is_control());
        assert!(MsgType::PlanReject.is_control());
        assert!(!MsgType::Heartbeat.is_control());
        assert!(!MsgType::AuditExportChunk.is_control());
    }
}
