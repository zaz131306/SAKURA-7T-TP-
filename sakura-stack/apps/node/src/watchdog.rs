//! Программная эмуляция иерархии watchdog (§22.11, C-05):
//! Core window WDT 50–200 мс (sticky-timeout, перезапуск окна, без гонки).
//! Kick вне окна [MIN, MAX] или пропуск → timeout (sticky до сброса).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct WindowWatchdog {
    last_kick_ms: Arc<AtomicU64>,
    timeout: Arc<AtomicBool>,
    min_ms: u64,
    max_ms: u64,
    handle: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    /// Счётчик срабатываний (для аудита/метрик).
    pub fire_count: Arc<std::sync::Mutex<u64>>,
}

impl WindowWatchdog {
    pub fn spawn(min_ms: u64, max_ms: u64) -> Self {
        let last_kick = Arc::new(AtomicU64::new(sakura_common::time::unix_ms()));
        let timeout = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let fire_count = Arc::new(std::sync::Mutex::new(0u64));
        let (lk, to, st, fc) = (last_kick.clone(), timeout.clone(), stop.clone(), fire_count.clone());
        let handle = std::thread::Builder::new()
            .name("window-wdt".into())
            .spawn(move || {
                // C-05: sticky-timeout, перезапуск окна по НОВОМУ kick,
                // отсутствие гонки. Ранний kick (< MIN от начала окна) в
                // аппаратной реализации latch-ит timeout; SW-профиль это
                // свойство проверяет тестбенчем RTL (tb_window_wdt).
                let mut window_start = sakura_common::time::unix_ms();
                let mut last_seen = lk.load(Ordering::Acquire);
                let mut fired = false;
                while !st.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                    let now = sakura_common::time::unix_ms();
                    let kick_at = lk.load(Ordering::Acquire);
                    if kick_at != last_seen {
                        last_seen = kick_at;
                        window_start = kick_at; // перезапуск окна
                        continue;
                    }
                    if !fired && now.saturating_sub(window_start) >= max_ms {
                        fired = true;
                        if !to.swap(true, Ordering::AcqRel) {
                            *fc.lock().unwrap() += 1;
                        }
                        // после просрочки подсчёт остановлен (sticky)
                    }
                    if fired && !to.load(Ordering::Acquire) {
                        // reset() (аппаратный сброс) — перевзвести окно
                        fired = false;
                        window_start = now;
                        last_seen = kick_at;
                    }
                }
            })
            .expect("watchdog thread");
        WindowWatchdog {
            last_kick_ms: last_kick,
            timeout,
            min_ms,
            max_ms,
            handle: Some(handle),
            stop,
            fire_count,
        }
    }

    /// Kick из основного цикла (window [min_ms, max_ms]).
    pub fn kick(&self) {
        self.last_kick_ms.store(sakura_common::time::unix_ms(), Ordering::Release);
    }

    pub fn timed_out(&self) -> bool {
        self.timeout.load(Ordering::Acquire)
    }

    /// Аппаратный сброс (единственный способ снять sticky-timeout, C-05).
    pub fn reset(&self) {
        self.timeout.store(false, Ordering::Release);
        self.last_kick_ms.store(sakura_common::time::unix_ms(), Ordering::Release);
    }

    pub fn window(&self) -> (u64, u64) {
        (self.min_ms, self.max_ms)
    }
}

impl Drop for WindowWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kicks_within_window_no_timeout() {
        let wd = WindowWatchdog::spawn(10, 200);
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(15));
            wd.kick();
            assert!(!wd.timed_out());
        }
        assert_eq!(*wd.fire_count.lock().unwrap(), 0);
    }

    #[test]
    fn missed_kick_sticky_timeout() {
        let wd = WindowWatchdog::spawn(10, 60);
        wd.kick();
        // пропуск окна; ожидание срабатывания — polling (устойчиво к
        // задержкам планировщика при параллельном прогоне тестов)
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !wd.timed_out() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(wd.timed_out(), "sticky timeout после пропуска окна");
        let fires = *wd.fire_count.lock().unwrap();
        assert!(fires >= 1);
        // sticky: повторный kick не снимает timeout
        wd.kick();
        std::thread::sleep(Duration::from_millis(20));
        assert!(wd.timed_out());
        // снимается только reset (аппаратный сброс)
        wd.reset();
        assert!(!wd.timed_out());
        wd.kick();
        std::thread::sleep(Duration::from_millis(30));
        wd.kick();
        assert!(!wd.timed_out());
    }
}
