//! Время платформы: unix-секунды/миллисекунды, ISO-8601 (UTC).

use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn unix_s() -> u64 {
    unix_ms() / 1000
}

/// ISO-8601 (UTC) — для журналов и экспорта.
pub fn iso8601(sec: u64) -> String {
    let days = (sec / 86400) as i64;
    let rem = sec % 86400;
    let hh = rem / 3600;
    let mi = (rem % 3600) / 60;
    let ss = rem % 60;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dd = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yy = if mo <= 2 { y0 + 1 } else { y0 };
    format!("{yy:04}-{mo:02}-{dd:02}T{hh:02}:{mi:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_known() {
        assert_eq!(iso8601(1_790_899_200), "2026-10-02T00:00:00Z");
        assert_eq!(iso8601(1_760_000_000), "2025-10-09T08:53:20Z");
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn monotonic_now() {
        let a = unix_ms();
        let b = unix_ms();
        assert!(b >= a);
        assert!(unix_s() > 1_700_000_000);
    }
}
