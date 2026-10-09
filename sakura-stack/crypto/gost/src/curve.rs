//! Эллиптическая кривая ГОСТ Р 34.10-2012 (256 бит).
//! Параметры: id-tc26-gost-3410-2012-256-paramSetA (RFC 7836 §5.2.1, A.2),
//! каноническая форма y² = x³ + ax + b (mod p).
//!
//! Точки в якобиановых координатах, значения — в форме Монтгомери;
//! преобразование в аффинные/натуральные координаты на границах API.

use crate::u256::{Mont, U256};
use std::sync::OnceLock;

/// Аффинная точка в натуральных координатах (big-endian сериализация X||Y).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: U256,
    pub y: U256,
    pub infinity: bool,
}

impl AffinePoint {
    pub const INFINITY: AffinePoint = AffinePoint { x: U256::ZERO, y: U256::ZERO, infinity: true };

    /// Публичный ключ: 64 байта = X_be(32) || Y_be(32).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x.to_be_bytes());
        out[32..].copy_from_slice(&self.y.to_be_bytes());
        out
    }

    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&b[..32]);
        yb.copy_from_slice(&b[32..]);
        AffinePoint { x: U256::from_be_bytes(&xb), y: U256::from_be_bytes(&yb), infinity: false }
    }
}

/// Точка в якобиановых координатах, значения в форме Монтгомери mod p.
#[derive(Clone, Copy, Debug)]
pub struct JacPoint {
    pub x: U256,
    pub y: U256,
    pub z: U256,
}

impl JacPoint {
    fn infinity_mont(one_m: U256) -> Self {
        // Z = 0 → бесконечность
        JacPoint { x: one_m, y: one_m, z: U256::ZERO }
    }
    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }
}

pub struct Curve {
    pub p: U256,
    pub q: U256,
    pub a: U256,
    pub b: U256,
    pub gx: U256,
    pub gy: U256,
    /// m = cofactor·q (порядок группы точек); для paramSetA cofactor = 4.
    pub cofactor: u64,
    pub mont_p: Mont,
    pub mont_q: Mont,
    // предварительно вычисленные константы в форме Монтгомери (mod p)
    a_m: U256,
    one_m: U256,
    two_m: U256,
    three_m: U256,
    eight_m: U256,
    g: JacPoint,
}

fn hx(s: &str) -> U256 {
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_owned() };
    let v = sakura_common::hex::decode(&s).expect("curve const hex");
    assert!(v.len() <= 32, "curve const must fit in 256 bits");
    let mut b = [0u8; 32];
    b[32 - v.len()..].copy_from_slice(&v);
    U256::from_be_bytes(&b)
}

impl Curve {
    /// paramSetA (единственный разрешённый 256-битный набор КР-1/§23.2.1).
    pub fn paramset_a() -> &'static Curve {
        static INSTANCE: OnceLock<Curve> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let p = hx(crate::kat::CURVE_P);
            let q = hx(crate::kat::CURVE_Q);
            let a = hx(crate::kat::CURVE_A);
            let b = hx(crate::kat::CURVE_B);
            let gx = hx(crate::kat::CURVE_X);
            let gy = hx(crate::kat::CURVE_Y);
            let mont_p = Mont::new(p);
            let mont_q = Mont::new(q);
            // cofactor: m = cofactor·q; m для paramSetA = 2²⁵⁶+δ > U256,
            // поэтому сравнение выполняется в 5-словах (264 бита).
            let mut mhex = crate::kat::CURVE_M.to_owned();
            if mhex.len() % 2 == 1 {
                mhex.insert(0, '0');
            }
            let m_bytes = sakura_common::hex::decode(&mhex).expect("curve m hex");
            assert!(m_bytes.len() <= 40);
            let mut m_limbs = [0u64; 5];
            {
                let mut padded = vec![0u8; 40 - m_bytes.len()];
                padded.extend_from_slice(&m_bytes);
                for i in 0..5 {
                    let mut w = [0u8; 8];
                    w.copy_from_slice(&padded[i * 8..i * 8 + 8]);
                    m_limbs[4 - i] = u64::from_be_bytes(w);
                }
            }
            let mut cofactor = 0u64;
            for c in 1u64..16 {
                // q·c в 5 словах
                let mut acc = [0u64; 5];
                let mut carry: u128 = 0;
                for i in 0..4 {
                    let t = q.0[i] as u128 * c as u128 + carry;
                    acc[i] = t as u64;
                    carry = t >> 64;
                }
                acc[4] = carry as u64;
                if acc == m_limbs {
                    cofactor = c;
                    break;
                }
            }
            assert!(cofactor >= 1, "m != c·q for c in 1..16");

            let one_m = mont_p.to_mont(&U256::ONE);
            let two_m = mont_p.to_mont(&U256::from_u64(2));
            let three_m = mont_p.to_mont(&U256::from_u64(3));
            let eight_m = mont_p.to_mont(&U256::from_u64(8));
            let a_m = mont_p.to_mont(&a);
            let gx_m = mont_p.to_mont(&gx);
            let gy_m = mont_p.to_mont(&gy);
            let g = JacPoint { x: gx_m, y: gy_m, z: one_m };

            let curve = Curve {
                p, q, a, b, gx, gy, cofactor,
                mont_p, mont_q,
                a_m, one_m, two_m, three_m, eight_m, g,
            };
            // самопроверка: генератор на кривой и q·G = O (§23.8 startup self-test)
            let gaf = curve.to_affine(&curve.g);
            assert!(curve.is_on_curve(&gaf), "generator not on curve");
            let qg = curve.scalar_mul(&q, None);
            assert!(qg.infinity, "q·G != O");
            curve
        })
    }

    // ---- полевая арифметика (форма Монтгомери) ----

    #[inline]
    fn fa(&self, a: &U256, b: &U256) -> U256 {
        a.add_mod(b, &self.p)
    }
    #[inline]
    fn fs(&self, a: &U256, b: &U256) -> U256 {
        a.sub_mod(b, &self.p)
    }
    #[inline]
    fn finv(&self, a: &U256) -> U256 {
        self.mont_p.inv(a)
    }

    // ---- якобиановы операции ----

    fn jac_double(&self, pt: &JacPoint) -> JacPoint {
        if pt.is_infinity() || pt.y.is_zero() {
            return JacPoint::infinity_mont(self.one_m);
        }
        let m = &self.mont_p;
        let xx = m.mul(&pt.x, &pt.x); // A = X²
        let yy = m.mul(&pt.y, &pt.y); // B = Y²
        let cc = m.mul(&yy, &yy); // C = B²
        // D = 2((X+B)² − A − C)
        let xb = self.fa(&pt.x, &yy);
        let xb2 = m.mul(&xb, &xb);
        let d = m.mul(&self.two_m, &self.fs(&self.fs(&xb2, &xx), &cc));
        // E = 3A + a·Z⁴
        let z2 = m.mul(&pt.z, &pt.z);
        let z4 = m.mul(&z2, &z2);
        let az4 = m.mul(&self.a_m, &z4);
        let three_a = m.mul(&self.three_m, &xx);
        let e = self.fa(&three_a, &az4);
        let f = m.mul(&e, &e);
        // X' = F − 2D
        let two_d = m.mul(&self.two_m, &d);
        let x3 = self.fs(&f, &two_d);
        // Y' = E(D − X') − 8C
        let eight_c = m.mul(&self.eight_m, &cc);
        let y3 = self.fs(&m.mul(&e, &self.fs(&d, &x3)), &eight_c);
        // Z' = 2·Y·Z
        let z3 = m.mul(&self.two_m, &m.mul(&pt.y, &pt.z));
        JacPoint { x: x3, y: y3, z: z3 }
    }

    pub fn jac_add(&self, p1: &JacPoint, p2: &JacPoint) -> JacPoint {
        if p1.is_infinity() {
            return *p2;
        }
        if p2.is_infinity() {
            return *p1;
        }
        let m = &self.mont_p;
        let z1z1 = m.mul(&p1.z, &p1.z);
        let z2z2 = m.mul(&p2.z, &p2.z);
        let u1 = m.mul(&p1.x, &z2z2);
        let u2 = m.mul(&p2.x, &z1z1);
        let s1 = m.mul(&m.mul(&p1.y, &p2.z), &z2z2);
        let s2 = m.mul(&m.mul(&p2.y, &p1.z), &z1z1);
        if u1 == u2 {
            if s1 != s2 {
                return JacPoint::infinity_mont(self.one_m);
            }
            return self.jac_double(p1);
        }
        let h = self.fs(&u2, &u1);
        let r = self.fs(&s2, &s1);
        let hh = m.mul(&h, &h);
        let hhh = m.mul(&h, &hh);
        let u1hh = m.mul(&u1, &hh);
        let x3 = self.fs(&self.fs(&m.mul(&r, &r), &hhh), &m.mul(&self.two_m, &u1hh));
        let y3 = self.fs(&m.mul(&r, &self.fs(&u1hh, &x3)), &m.mul(&s1, &hhh));
        let z3 = m.mul(&m.mul(&p1.z, &p2.z), &h);
        JacPoint { x: x3, y: y3, z: z3 }
    }

    /// Скалярное умножение: k·base (base=None → генератор G).
    /// Double-and-add, старшие биты первыми.
    pub fn scalar_mul(&self, k: &U256, base: Option<&JacPoint>) -> AffinePoint {
        let bp = match base {
            Some(j) => *j,
            None => self.g,
        };
        let mut r = JacPoint::infinity_mont(self.one_m);
        let k = self.reduce_q(k);
        for i in (0..k.bits()).rev() {
            r = self.jac_double(&r);
            if k.bit(i) {
                r = self.jac_add(&r, &bp);
            }
        }
        self.to_affine(&r)
    }

    pub fn generator_jac(&self) -> JacPoint {
        self.g
    }

    pub fn affine_to_jac(&self, pt: &AffinePoint) -> JacPoint {
        if pt.infinity {
            return JacPoint::infinity_mont(self.one_m);
        }
        JacPoint { x: self.mont_p.to_mont(&pt.x), y: self.mont_p.to_mont(&pt.y), z: self.one_m }
    }

    pub fn to_affine(&self, pt: &JacPoint) -> AffinePoint {
        if pt.is_infinity() {
            return AffinePoint::INFINITY;
        }
        let m = &self.mont_p;
        let zi = self.finv(&pt.z);
        let zi2 = m.mul(&zi, &zi);
        let zi3 = m.mul(&zi2, &zi);
        AffinePoint {
            x: m.from_mont(&m.mul(&pt.x, &zi2)),
            y: m.from_mont(&m.mul(&pt.y, &zi3)),
            infinity: false,
        }
    }

    /// Проверка принадлежности кривой: y² = x³ + ax + b (mod p).
    pub fn is_on_curve(&self, pt: &AffinePoint) -> bool {
        if pt.infinity {
            return true;
        }
        if pt.x >= self.p || pt.y >= self.p {
            return false;
        }
        let lhs = self.mont_p.mul_nat(&pt.y, &pt.y);
        let x2 = self.mont_p.mul_nat(&pt.x, &pt.x);
        let x3 = self.mont_p.mul_nat(&x2, &pt.x);
        let ax = self.mont_p.mul_nat(&self.a, &pt.x);
        let rhs = x3.add_mod(&ax, &self.p).add_mod(&self.b, &self.p);
        lhs == rhs
    }

    /// k mod q (скаляр всегда приводится по порядку подгруппы).
    pub fn reduce_q(&self, k: &U256) -> U256 {
        let mut r = *k;
        while r >= self.q {
            let (d, _) = r.sbb(&self.q, false);
            r = d;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_selfchecks_and_point_math() {
        let c = Curve::paramset_a();
        assert_eq!(c.cofactor, 4);
        let g = AffinePoint { x: c.gx, y: c.gy, infinity: false };
        assert!(c.is_on_curve(&g));

        // 2G = G + G (double vs add consistency)
        let g2a = c.scalar_mul(&U256::from_u64(2), None);
        let gsum = {
            let jg = c.generator_jac();
            let sum = c.jac_add(&jg, &jg);
            c.to_affine(&sum)
        };
        assert_eq!(g2a, gsum);
        assert!(c.is_on_curve(&g2a));

        // (q−1)·G = −G
        let qm1 = c.q.sub_mod(&U256::ONE, &c.q);
        let qm1g = c.scalar_mul(&qm1, None);
        let neg_g_y = c.p.sub_mod(&g.y, &c.p);
        assert_eq!(qm1g.x, g.x);
        assert_eq!(qm1g.y, neg_g_y);

        // 5G = 2G + 3G
        let g5 = c.scalar_mul(&U256::from_u64(5), None);
        let g3 = c.scalar_mul(&U256::from_u64(3), None);
        let sum = c.to_affine(&c.jac_add(&c.affine_to_jac(&g2a), &c.affine_to_jac(&g3)));
        assert_eq!(g5, sum);

        // q·G = O уже проверено в конструкторе
        let _ = hx(crate::kat::CURVE_P); // константы доступны

        // bytes roundtrip
        let b = g5.to_bytes();
        assert_eq!(AffinePoint::from_bytes(&b), g5);
    }
}
