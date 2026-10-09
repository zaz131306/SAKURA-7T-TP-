//! GF(2¹⁰) для RS(544,514) KP4 (IEEE 802.3 Clause 91 / ГОСТ-профиль NPP):
//! примитивный полином p(x) = x¹⁰ + x³ + 1 (0x409), α = 2.

pub const FIELD_SIZE: usize = 1024;
pub const PRIM_POLY: u16 = 0x409; // x^10 + x^3 + 1

/// Таблицы exp/log (инициализируются лениво один раз).
pub struct Tables {
    pub exp: [u16; FIELD_SIZE * 2],
    pub log: [u16; FIELD_SIZE],
}

static TABLES: std::sync::OnceLock<Tables> = std::sync::OnceLock::new();

pub fn tables() -> &'static Tables {
    TABLES.get_or_init(|| {
        let mut exp = [0u16; FIELD_SIZE * 2];
        let mut log = [0u16; FIELD_SIZE];
        let mut x: u16 = 1;
        for i in 0..(FIELD_SIZE - 1) {
            exp[i] = x;
            log[x as usize] = i as u16;
            x <<= 1;
            if x & 0x400 != 0 {
                x ^= PRIM_POLY;
            }
        }
        // удвоение таблицы — удобства ради (a+b < 2·1023)
        for i in 0..(FIELD_SIZE - 1) {
            exp[FIELD_SIZE - 1 + i] = exp[i];
        }
        Tables { exp, log }
    })
}

#[inline]
pub fn mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as usize;
    let lb = t.log[b as usize] as usize;
    t.exp[la + lb]
}

#[inline]
pub fn inv(a: u16) -> u16 {
    assert!(a != 0, "inverse of zero");
    let t = tables();
    let la = t.log[a as usize] as usize;
    t.exp[FIELD_SIZE - 1 - la]
}

/// α^k (k может быть ≥ 1023 — приводится по модулю 1023).
#[inline]
pub fn alpha_pow(k: i64) -> u16 {
    let t = tables();
    let m = k.rem_euclid((FIELD_SIZE - 1) as i64) as usize;
    t.exp[m]
}

#[inline]
pub fn add(a: u16, b: u16) -> u16 {
    a ^ b
}

/// Полиномы — векторы коэффициентов по возрастанию степени: p[i] = x^i.
pub fn poly_mul(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut out = vec![0u16; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai == 0 {
            continue;
        }
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] ^= mul(ai, bj);
        }
    }
    out
}

/// Порождающий полином RS(544,514): g(x) = Π (x − α^i), i = 0..2t−1 (t=15).
pub fn generator_poly(nroots: usize) -> Vec<u16> {
    let mut g = vec![1u16];
    for i in 0..nroots {
        g = poly_mul(&g, &[alpha_pow(i as i64), 1]); // (α^i + x)
    }
    g
}

/// Вычисление полинома в точке (coef по возрастанию степени).
pub fn poly_eval(p: &[u16], x: u16) -> u16 {
    let mut acc = 0u16;
    for &c in p.iter().rev() {
        acc = add(mul(acc, x), c);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_basics() {
        // α примитивен: α^1023 = 1, все степени различны
        assert_eq!(alpha_pow(1023), 1);
        assert_eq!(alpha_pow(0), 1);
        assert_eq!(alpha_pow(1), 2);
        let mut seen = std::collections::HashSet::new();
        for k in 0..1023 {
            assert!(seen.insert(alpha_pow(k)), "α^{k} не уникален");
        }
        // a·a⁻¹ = 1
        for a in 1..1024u16 {
            assert_eq!(mul(a, inv(a)), 1);
        }
        // дистрибутивность выборочно
        for a in (1..1024u16).step_by(101) {
            for b in (1..1024u16).step_by(97) {
                assert_eq!(mul(a, add(b, 7)), add(mul(a, b), mul(a, 7)));
            }
        }
    }

    #[test]
    fn generator_roots() {
        let g = generator_poly(30);
        assert_eq!(g.len(), 31);
        assert_eq!(g[30], 1); // старший коэффициент
        for i in 0..30 {
            assert_eq!(poly_eval(&g, alpha_pow(i)), 0, "α^{i} — корень g(x)");
        }
    }
}
