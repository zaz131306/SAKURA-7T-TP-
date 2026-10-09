//! 256-битная беззнаковая арифметика и Монтгомери-умножение.
//! Основа ГОСТ Р 34.10-2012 (криптографическая математика платформы).
#![allow(clippy::needless_range_loop)]

use zeroize::Zeroize;

/// Little-endian limbs: v = l[0] + l[1]·2⁶⁴ + l[2]·2¹²⁸ + l[3]·2¹⁹².
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl Zeroize for U256 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i].cmp(&other.0[i]);
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);

    pub fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    pub fn from_be_bytes(b: &[u8; 32]) -> Self {
        let mut l = [0u64; 4];
        for i in 0..4 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            l[3 - i] = u64::from_be_bytes(w);
        }
        U256(l)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    pub fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    pub fn bits(&self) -> usize {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Сложение с переносом; возвращает (sum, carry).
    pub fn adc(&self, other: &Self, carry: bool) -> (Self, bool) {
        let mut l = [0u64; 4];
        let mut c = carry as u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + other.0[i] as u128 + c;
            l[i] = s as u64;
            c = s >> 64;
        }
        (U256(l), c != 0)
    }

    /// Вычитание с заёмом; возвращает (diff, borrow).
    pub fn sbb(&self, other: &Self, borrow: bool) -> (Self, bool) {
        let mut l = [0u64; 4];
        let mut b = borrow;
        for i in 0..4 {
            let (d, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d, b2) = d.overflowing_sub(b as u64);
            l[i] = d;
            b = b1 || b2;
        }
        (U256(l), b)
    }

    pub fn add_mod(&self, other: &Self, n: &Self) -> Self {
        let (s, c) = self.adc(other, false);
        let (r, b) = s.sbb(n, false);
        if c || !b {
            r
        } else {
            s
        }
    }

    pub fn sub_mod(&self, other: &Self, n: &Self) -> Self {
        let (d, b) = self.sbb(other, false);
        if b {
            // d + n
            let (r, _) = d.adc(n, false);
            r
        } else {
            d
        }
    }

    pub fn neg_mod(&self, n: &Self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            n.sub_mod(self, n)
        }
    }

    /// Полное умножение 256×256 → 512.
    pub fn mul_wide(&self, other: &Self) -> [u64; 8] {
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let cur = t[i + j] as u128
                    + self.0[i] as u128 * other.0[j] as u128
                    + carry;
                t[i + j] = cur as u64;
                carry = cur >> 64;
            }
            t[i + 4] = carry as u64;
        }
        t
    }
}

/// Параметры Монтгомери для нечётного модуля n: n0inv = -n⁻¹ mod 2⁶⁴,
/// r2 = 2⁵¹² mod n. Значения хранятся в обычной (не Монтгомери) форме.
#[derive(Clone, Debug)]
pub struct Mont {
    pub n: U256,
    pub n0inv: u64,
    pub r2: U256,
}

impl Mont {
    /// Создать контекст для нечётного модуля n > 1.
    pub fn new(n: U256) -> Self {
        assert!(n.0[0] & 1 == 1, "Montgomery requires odd modulus");
        assert!(n > U256::ONE);
        // inv = n[0]^{-1} mod 2^64 (Ньютон: x ← x(2 − n·x))
        let mut inv: u64 = n.0[0];
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n.0[0].wrapping_mul(inv)));
        }
        debug_assert!(inv.wrapping_mul(n.0[0]) == 1);
        let n0inv = inv.wrapping_neg(); // -n⁻¹ mod 2⁶⁴
        // r2 = 2^512 mod n: 512 удвоений единицы
        let mut r2 = U256::ONE;
        for _ in 0..512 {
            r2 = r2.add_mod(&r2, &n);
        }
        Mont { n, n0inv, r2 }
    }

    /// Монтгомери-умножение: a·b·R⁻¹ mod n (входы/выход в Монтгомери-форме).
    pub fn mul(&self, a: &U256, b: &U256) -> U256 {
        let n = &self.n;
        let mut t = [0u64; 6];
        for i in 0..4 {
            // t += a · b[i]
            let mut carry: u128 = 0;
            for j in 0..4 {
                carry += t[j] as u128 + a.0[j] as u128 * b.0[i] as u128;
                t[j] = carry as u64;
                carry >>= 64;
            }
            carry += t[4] as u128;
            t[4] = carry as u64;
            t[5] += (carry >> 64) as u64;
            // m = t[0] · n0inv mod 2⁶⁴; t += n · m; t >>= 64
            let m = t[0].wrapping_mul(self.n0inv);
            let mut carry: u128 = t[0] as u128 + n.0[0] as u128 * m as u128;
            carry >>= 64; // t[0] обнуляется
            for j in 1..4 {
                carry += t[j] as u128 + n.0[j] as u128 * m as u128;
                t[j - 1] = carry as u64;
                carry >>= 64;
            }
            carry += t[4] as u128;
            t[3] = carry as u64;
            carry = (carry >> 64) + t[5] as u128;
            t[4] = carry as u64;
            t[5] = 0;
        }
        // t < 2n → условное вычитание
        let mut r = U256([t[0], t[1], t[2], t[3]]);
        if t[4] == 1 {
            // r + 2²⁵⁶ − n
            let (d, _) = r.sbb(n, false);
            r = d;
        } else if r >= *n {
            let (d, _) = r.sbb(n, false);
            r = d;
        }
        r
    }

    pub fn to_mont(&self, a: &U256) -> U256 {
        self.mul(a, &self.r2)
    }

    pub fn from_mont(&self, a: &U256) -> U256 {
        self.mul(a, &U256::ONE)
    }

    /// Степень в Монтгомери-форме: base^exp (base в Монтгомери-форме).
    pub fn pow(&self, base_mont: &U256, exp: &U256) -> U256 {
        let mut r = self.to_mont(&U256::ONE);
        for i in (0..exp.bits()).rev() {
            r = self.mul(&r, &r);
            if exp.bit(i) {
                r = self.mul(&r, base_mont);
            }
        }
        r
    }

    /// Обращение по малой теореме Ферма (n — простое).
    pub fn inv(&self, a_mont: &U256) -> U256 {
        // a^{-1} = a^{n-2}; exp = n-2 в обычной форме
        let (e, _) = self.n.sbb(&U256::from_u64(2), false);
        self.pow(a_mont, &e)
    }

    /// a·b mod n (входы в обычной форме, выход в обычной).
    pub fn mul_nat(&self, a: &U256, b: &U256) -> U256 {
        let am = self.to_mont(a);
        let bm = self.to_mont(b);
        self.from_mont(&self.mul(&am, &bm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(h: &str) -> U256 {
        let b = sakura_common::hex::decode(h).unwrap();
        let mut a = [0u8; 32];
        a[32 - b.len()..].copy_from_slice(&b);
        U256::from_be_bytes(&a)
    }

    #[test]
    fn add_sub_basics() {
        let a = U256::from_u64(5);
        let b = U256::from_u64(7);
        let (s, c) = a.adc(&b, false);
        assert_eq!(s, U256::from_u64(12));
        assert!(!c);
        let (d, bo) = a.sbb(&b, false);
        assert!(bo);
        let _ = d;
        // переполнение 2^256-1 + 1
        let max = U256([u64::MAX; 4]);
        let (s, c) = max.adc(&U256::ONE, false);
        assert_eq!(s, U256::ZERO);
        assert!(c);
    }

    #[test]
    fn mul_wide_known() {
        let a = x("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        let b = U256::from_u64(2);
        let w = a.mul_wide(&b);
        // 2·(2^256−1) = 2^257 − 2
        assert_eq!(w[0], u64::MAX - 1);
        assert_eq!(w[1], u64::MAX);
        assert_eq!(w[4], 1);
    }

    #[test]
    fn mont_mul_prime() {
        // p = 2^256 − 189 (простое) — проверка против школьного mul_wide+mod
        let p = {
            let (r, _) = U256([u64::MAX; 4]).sbb(&U256::from_u64(188), false);
            r
        };
        let m = Mont::new(p);
        let a = x("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        let b = x("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210");
        let got = m.mul_nat(&a, &b);
        // эталон: школьное умножение + редукция повторным вычитанием сдвигом
        let wide = a.mul_wide(&b);
        let want = mod_wide(&wide, &p);
        assert_eq!(got, want);
        // roundtrip Монтгомери
        let am = m.to_mont(&a);
        assert_eq!(m.from_mont(&am), a);
        // (a·a^{-1}) mod p = 1
        let am2 = m.to_mont(&a);
        let inv = m.inv(&am2);
        let one_m = m.mul(&am2, &inv);
        assert_eq!(m.from_mont(&one_m), U256::ONE);
    }

    /// Школьная редукция 512-битного числа по модулю (для теста).
    fn mod_wide(w: &[u64; 8], n: &U256) -> U256 {
        let mut r = U256::ZERO;
        for i in (0..8).rev() {
            // r = r·2⁶⁴ + w[i]  (mod n) — через 64 шага удвоения
            for b in (0..64).rev() {
                r = r.add_mod(&r, n);
                let bit = (w[i] >> b) & 1;
                if bit == 1 {
                    r = r.add_mod(&U256::ONE, n);
                }
            }
        }
        r
    }

    #[test]
    fn bytes_roundtrip() {
        let a = x("A1B2C3D4E5F60718293A4B5C6D7E8F900112233445566778899AABBCCDDEEFF0");
        assert_eq!(U256::from_be_bytes(&a.to_be_bytes()), a);
    }
}
