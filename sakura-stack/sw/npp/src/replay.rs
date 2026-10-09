//! Anti-replay окно (§13.17: Seq + timestamp + nonce; REPLAY-001, BC-27):
//! - monotonic seq на направление/сессию;
//! - скользящее окно принятых seq (битовая карта);
//! - timestamp skew window (синхронизированное время PTP/holdover);
//! - replay attempts фиксируются с error code (§13.20.2).

use crate::msg::NppErrCode;

pub const WINDOW_BITS: usize = 256;

pub struct ReplayWindow {
    max_seq: Option<u64>,
    bitmap: [bool; WINDOW_BITS],
    /// Допустимый skew timestamp, сек (§13.20.2).
    pub max_skew_s: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(5)
    }
}

impl ReplayWindow {
    pub fn new(max_skew_s: u64) -> Self {
        ReplayWindow { max_seq: None, bitmap: [false; WINDOW_BITS], max_skew_s }
    }

    /// Проверка seq: Ok(()) — принять; Err — ReplayDetected / SeqOutOfWindow.
    /// При успехе окно обновляется (check-and-set, §13.20.2).
    pub fn check_seq(&mut self, seq: u64) -> Result<(), NppErrCode> {
        match self.max_seq {
            None => {
                self.max_seq = Some(seq);
                self.bitmap = [false; WINDOW_BITS];
                self.bitmap[0] = true;
                Ok(())
            }
            Some(max) => {
                if seq > max {
                    let shift = (seq - max) as usize;
                    if shift >= WINDOW_BITS {
                        self.bitmap = [false; WINDOW_BITS];
                    } else {
                        // сдвиг окна
                        for i in (shift..WINDOW_BITS).rev() {
                            self.bitmap[i] = self.bitmap[i - shift];
                        }
                        for i in 0..shift.min(WINDOW_BITS) {
                            self.bitmap[i] = false;
                        }
                    }
                    self.bitmap[0] = true;
                    self.max_seq = Some(seq);
                    Ok(())
                } else {
                    let age = max - seq;
                    if age >= WINDOW_BITS as u64 {
                        Err(NppErrCode::SeqOutOfWindow)
                    } else if self.bitmap[age as usize] {
                        Err(NppErrCode::ReplayDetected)
                    } else {
                        self.bitmap[age as usize] = true;
                        Ok(())
                    }
                }
            }
        }
    }

    /// Проверка timestamp против локального синхронизированного времени.
    pub fn check_timestamp(&self, ts_s: u64, now_s: u64) -> Result<(), NppErrCode> {
        let diff = if ts_s > now_s { ts_s - now_s } else { now_s - ts_s };
        if diff > self.max_skew_s {
            Err(NppErrCode::SeqOutOfWindow) // timestamp skew (§13.20.2)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_accepts() {
        let mut w = ReplayWindow::new(5);
        for s in [1u64, 2, 3, 10, 300, 301] {
            assert_eq!(w.check_seq(s), Ok(()), "seq {s}");
        }
    }

    #[test]
    fn duplicates_are_replay() {
        let mut w = ReplayWindow::new(5);
        w.check_seq(5).unwrap();
        w.check_seq(6).unwrap();
        assert_eq!(w.check_seq(5), Err(NppErrCode::ReplayDetected));
        assert_eq!(w.check_seq(6), Err(NppErrCode::ReplayDetected));
        // старый, но не виденный в окне — принимается (out-of-order)
        assert_eq!(w.check_seq(4), Ok(()));
        assert_eq!(w.check_seq(4), Err(NppErrCode::ReplayDetected));
    }

    #[test]
    fn out_of_window_rejected() {
        let mut w = ReplayWindow::new(5);
        w.check_seq(1000).unwrap();
        // seq младше окна (1000 − 256)
        assert_eq!(w.check_seq(700), Err(NppErrCode::SeqOutOfWindow));
        // граница окна — принимается
        assert_eq!(w.check_seq(1000 - 255), Ok(()));
    }

    #[test]
    fn big_jump_resets_window() {
        let mut w = ReplayWindow::new(5);
        w.check_seq(1).unwrap();
        w.check_seq(10_000).unwrap();
        assert_eq!(w.check_seq(1), Err(NppErrCode::SeqOutOfWindow));
    }

    #[test]
    fn timestamp_skew() {
        let w = ReplayWindow::new(5);
        assert_eq!(w.check_timestamp(100, 102), Ok(()));
        assert_eq!(w.check_timestamp(108, 102), Err(NppErrCode::SeqOutOfWindow));
        assert_eq!(w.check_timestamp(90, 102), Err(NppErrCode::SeqOutOfWindow));
    }
}
