//! Boot FSM (§13.16.1):
//!
//! ```text
//! POWER_ON → ROM_VERIFY_PBL → PBL_VERIFY_SBL → SBL_VERIFY_KERNEL
//!   → KERNEL_START → CONTROL_SERVICES_START → HSM_ATTEST
//!   → KEY_RELEASE_POLICY_CHECK → RUNTIME_READY
//! Failure paths: BOOT_FAIL_COUNT++; <3 → RETRY; ≥3 → RECOVERY_MODE;
//! tamper → LOCKDOWN + ZEROIZE.
//! ```

use crate::image::BootError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootState {
    PowerOn,
    RomVerifyPbl,
    PblVerifySbl,
    SblVerifyKernel,
    KernelStart,
    ControlServicesStart,
    HsmAttest,
    KeyReleasePolicyCheck,
    RuntimeReady,
    Retry,
    RecoveryMode,
    LockdownZeroize,
}

pub const BOOT_FAIL_LIMIT: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootEvent {
    /// Текущая стадия завершена успешно.
    StageOk,
    /// Текущая стадия провалена.
    StageFailed(BootError),
    /// Tamper-сенсор (§22.20) — в любой точке.
    TamperDetected,
    /// Повторная попытка загрузки выполнена (RETRY → POWER_ON).
    RetryDone,
}

pub struct BootFsm {
    pub state: BootState,
    pub fail_count: u32,
    pub last_error: Option<BootError>,
}

impl Default for BootFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl BootFsm {
    pub fn new() -> Self {
        BootFsm { state: BootState::PowerOn, fail_count: 0, last_error: None }
    }

    pub fn is_terminal_ok(&self) -> bool {
        self.state == BootState::RuntimeReady
    }

    /// Следующая стадия основной цепочки.
    fn next_stage(s: BootState) -> Option<BootState> {
        use BootState::*;
        Some(match s {
            PowerOn => RomVerifyPbl,
            RomVerifyPbl => PblVerifySbl,
            PblVerifySbl => SblVerifyKernel,
            SblVerifyKernel => KernelStart,
            KernelStart => ControlServicesStart,
            ControlServicesStart => HsmAttest,
            HsmAttest => KeyReleasePolicyCheck,
            KeyReleasePolicyCheck => RuntimeReady,
            RuntimeReady => return None,
            _ => return None,
        })
    }

    pub fn on_event(&mut self, ev: BootEvent) -> BootState {
        use BootState::*;
        match ev {
            BootEvent::TamperDetected => {
                self.state = LockdownZeroize;
                self.state
            }
            BootEvent::RetryDone => {
                if self.state == Retry {
                    self.state = PowerOn;
                }
                self.state
            }
            BootEvent::StageOk => {
                if matches!(self.state, Retry | RecoveryMode | LockdownZeroize | RuntimeReady) {
                    return self.state;
                }
                if let Some(n) = Self::next_stage(self.state) {
                    self.state = n;
                    if self.state == RuntimeReady {
                        self.fail_count = 0; // успешная загрузка
                    }
                }
                self.state
            }
            BootEvent::StageFailed(err) => {
                self.last_error = Some(err);
                if matches!(self.state, LockdownZeroize | RecoveryMode) {
                    return self.state;
                }
                self.fail_count = self.fail_count.saturating_add(1);
                self.state = if self.fail_count >= BOOT_FAIL_LIMIT {
                    RecoveryMode
                } else {
                    Retry
                };
                self.state
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path() {
        let mut f = BootFsm::new();
        assert_eq!(f.state, BootState::PowerOn);
        let stages = [
            BootState::RomVerifyPbl,
            BootState::PblVerifySbl,
            BootState::SblVerifyKernel,
            BootState::KernelStart,
            BootState::ControlServicesStart,
            BootState::HsmAttest,
            BootState::KeyReleasePolicyCheck,
            BootState::RuntimeReady,
        ];
        for want in stages {
            let got = f.on_event(BootEvent::StageOk);
            assert_eq!(got, want);
        }
        assert!(f.is_terminal_ok());
        assert_eq!(f.fail_count, 0);
    }

    #[test]
    fn failure_retry_then_recovery() {
        let mut f = BootFsm::new();
        f.on_event(BootEvent::StageOk); // → RomVerifyPbl
        assert_eq!(
            f.on_event(BootEvent::StageFailed(BootError::GostSignatureInvalid)),
            BootState::Retry
        );
        assert_eq!(f.fail_count, 1);
        assert_eq!(f.last_error, Some(BootError::GostSignatureInvalid));
        f.on_event(BootEvent::RetryDone);
        assert_eq!(f.state, BootState::PowerOn);
        f.on_event(BootEvent::StageOk);
        f.on_event(BootEvent::StageFailed(BootError::HashMismatch));
        assert_eq!(f.state, BootState::Retry);
        f.on_event(BootEvent::RetryDone);
        f.on_event(BootEvent::StageOk);
        f.on_event(BootEvent::StageFailed(BootError::HashMismatch));
        // третья неудача → RECOVERY_MODE (§13.16.1)
        assert_eq!(f.state, BootState::RecoveryMode);
        assert_eq!(f.fail_count, 3);
        // recovery mode не обходит проверки: последующие ошибки не меняют state
        f.on_event(BootEvent::StageFailed(BootError::HashMismatch));
        assert_eq!(f.state, BootState::RecoveryMode);
    }

    #[test]
    fn tamper_lockdown() {
        let mut f = BootFsm::new();
        f.on_event(BootEvent::StageOk);
        assert_eq!(f.on_event(BootEvent::TamperDetected), BootState::LockdownZeroize);
        // из lockdown нет выхода по StageOk
        f.on_event(BootEvent::StageOk);
        assert_eq!(f.state, BootState::LockdownZeroize);
    }
}
