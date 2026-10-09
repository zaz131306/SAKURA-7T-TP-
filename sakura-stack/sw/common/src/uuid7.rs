//! UUIDv7 (RFC 9562): 48 бит unix_ms | ver=7 | rand_a 12 бит | var=10 | rand_b 62 бита.
//! DM-1: node_id, cluster_id, cert_id, plan_id, command_id, audit ref — uuid7.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid7(pub [u8; 16]);

impl Uuid7 {
    /// Создание из текущего времени и источника случайных байт.
    pub fn now() -> Self {
        let ms = crate::time::unix_ms();
        let mut rand = [0u8; 10];
        crate::rand::fill(&mut rand);
        Self::from_ms_rand(ms, rand)
    }

    /// Детерминированное создание (для тестов/KAT).
    pub fn from_ms_rand(ms: u64, rand10: [u8; 10]) -> Self {
        let mut b = [0u8; 16];
        b[0..6].copy_from_slice(&ms.to_be_bytes()[2..8]);
        b[6..16].copy_from_slice(&rand10);
        b[6] = (b[6] & 0x0f) | 0x70; // version 7
        b[8] = (b[8] & 0x3f) | 0x80; // variant 10
        Uuid7(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn unix_ms(&self) -> u64 {
        let mut t = [0u8; 8];
        t[2..8].copy_from_slice(&self.0[0..6]);
        u64::from_be_bytes(t)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.replace('-', "");
        if s.len() != 32 {
            return None;
        }
        let b = crate::hex::decode(&s).ok()?;
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        if a[6] >> 4 != 7 || a[8] >> 6 != 2 {
            return None;
        }
        Some(Uuid7(a))
    }
}

impl fmt::Display for Uuid7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Uuid7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid7({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_parse() {
        let u = Uuid7::from_ms_rand(0x018f_2b1c_0000, [0xab; 10]);
        let s = u.to_string();
        assert_eq!(&s[14..15], "7", "version nibble");
        assert!(s.starts_with("018f2b1c-0000-7"), "{s}");
        assert!(s.chars().nth(19) == Some('a') || s.chars().nth(19) == Some('b'));
        let p = Uuid7::parse(&s).unwrap();
        assert_eq!(p, u);
        assert_eq!(u.unix_ms(), 0x018f_2b1c_0000);
        // variant bits: байт 8 = 0x80..0xBF
        assert!((u.0[8] & 0xc0) == 0x80);
    }

    #[test]
    fn monotonic_ordering() {
        let a = Uuid7::from_ms_rand(1000, [0; 10]);
        let b = Uuid7::from_ms_rand(1001, [0; 10]);
        assert!(a < b);
    }
}
