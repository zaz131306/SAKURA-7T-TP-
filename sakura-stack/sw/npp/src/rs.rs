//! RS(544,514) over GF(2¹⁰) — FEC профиль NPP (§13.3, BC-26, KP4-семейство):
//! t = 15 исправляемых символов на кодовое слово; систематическое кодирование;
//! декодирование: синдромы → Berlekamp-Massey → Chien → Forney;
//! остаточная проверка синдромов (miscorrection guard).
//!
//! Выравнивание (BC-26): область данных (header+payload+padding) кратна
//! REGION_UNIT_BYTES = 1285 Б = 10280 бит = 2 кодовых слова × 5140 бит.
//! Parity: 30 символов (300 бит) на кодовое слово, упаковка MSB-first.

use crate::gf1024::{add, alpha_pow, inv, mul, poly_eval};

pub const RS_N: usize = 544;
pub const RS_K: usize = 514;
pub const RS_T: usize = 15;
pub const RS_PARITY: usize = 30;
pub const SYMBOL_BITS: usize = 10;
pub const CW_BITS: usize = RS_K * SYMBOL_BITS; // 5140
pub const REGION_UNIT_BYTES: usize = CW_BITS * 2 / 8; // 1285 (2 кодовых слова)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsError {
    BadRegionLen,
    BadFecLen,
    Uncorrectable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeOutcome {
    pub corrected_region: Vec<u8>,
    pub corrected_symbols: usize,
    pub used_fec: bool,
}

/// Упаковка байтов в 10-битовые символы (MSB-first по битовому потоку).
pub fn pack_symbols(data: &[u8]) -> Vec<u16> {
    let total_bits = data.len() * 8;
    let nsyms = total_bits.div_ceil(SYMBOL_BITS);
    let mut out = Vec::with_capacity(nsyms);
    for s in 0..nsyms {
        let mut v: u16 = 0;
        for b in 0..SYMBOL_BITS {
            let bit = s * SYMBOL_BITS + b;
            if bit < total_bits {
                let byte = data[bit / 8];
                let on = (byte >> (7 - (bit % 8))) & 1;
                v = (v << 1) | on as u16;
            } else {
                v <<= 1; // хвостовой ноль-паддинг последнего символа
            }
        }
        out.push(v);
    }
    out
}

/// Обратная упаковка (обрезает хвостовые биты последнего символа до 8·len).
pub fn unpack_symbols(syms: &[u16], out_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_bytes];
    for (s, &v) in syms.iter().enumerate() {
        for b in 0..SYMBOL_BITS {
            let bit = s * SYMBOL_BITS + b;
            if bit >= out_bytes * 8 {
                break;
            }
            let on = ((v >> (SYMBOL_BITS - 1 - b)) & 1) as u8;
            out[bit / 8] |= on << (7 - (bit % 8));
        }
    }
    out
}

/// Порождающий полином (коэффициенты по возрастанию степени, g[30] = 1).
fn generator() -> &'static Vec<u16> {
    static G: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();
    G.get_or_init(|| {
        let mut g = vec![1u16];
        for i in 0..RS_PARITY {
            // умножение на (x + α^i)
            let mut ng = vec![0u16; g.len() + 1];
            for (j, &c) in g.iter().enumerate() {
                ng[j + 1] ^= c;
                ng[j] ^= mul(c, alpha_pow(i as i64));
            }
            g = ng;
        }
        g
    })
}

/// Систематическое кодирование одного слова: 514 символов → 30 parity.
pub fn encode_cw(msg: &[u16]) -> [u16; RS_PARITY] {
    assert_eq!(msg.len(), RS_K);
    let g = generator();
    let mut r = [0u16; RS_PARITY]; // r[0] ↔ x^29 … r[29] ↔ x^0
    for &s in msg {
        let fb = s ^ r[0];
        r.copy_within(1..RS_PARITY, 0);
        r[RS_PARITY - 1] = 0;
        if fb != 0 {
            for j in 0..RS_PARITY {
                r[j] ^= mul(fb, g[RS_PARITY - 1 - j]);
            }
        }
    }
    r
}

fn syndromes(cw: &[u16; RS_N]) -> [u16; RS_PARITY] {
    let mut s = [0u16; RS_PARITY];
    for (j, sj) in s.iter_mut().enumerate() {
        let x = alpha_pow(j as i64);
        let mut acc = 0u16;
        for &c in cw.iter() {
            acc = add(mul(acc, x), c);
        }
        *sj = acc;
    }
    s
}

/// Berlekamp-Massey: по синдромам (S_0..S_29) — локатор Λ (по возрастанию).
fn berlekamp_massey(s: &[u16; RS_PARITY]) -> Vec<u16> {
    let mut c = vec![1u16]; // Λ
    let mut b = vec![1u16];
    let mut l = 0usize;
    let mut m = 1usize;
    let mut bb: u16 = 1;
    for n in 0..RS_PARITY {
        // расхождение d = S_n + Σ_{i=1..L} C_i S_{n-i}
        let mut d = s[n];
        for i in 1..=l.min(c.len().saturating_sub(1)).min(n) {
            d = add(d, mul(c[i], s[n - i]));
        }
        if d == 0 {
            m += 1;
        } else if 2 * l <= n {
            let t = c.clone();
            let coef = mul(d, inv(bb));
            c.resize(c.len().max(b.len() + m), 0);
            for (i, &bi) in b.iter().enumerate() {
                c[i + m] = add(c[i + m], mul(coef, bi));
            }
            l = n + 1 - l;
            b = t;
            bb = d;
            m = 1;
        } else {
            let coef = mul(d, inv(bb));
            c.resize(c.len().max(b.len() + m), 0);
            for (i, &bi) in b.iter().enumerate() {
                c[i + m] = add(c[i + m], mul(coef, bi));
            }
            m += 1;
        }
    }
    c.resize(l + 1, 0);
    c
}

/// Декодирование одного кодового слова (in-place коррекция).
/// Возвращает число исправленных символов или Uncorrectable.
pub fn decode_cw(cw: &mut [u16; RS_N]) -> Result<usize, RsError> {
    let s = syndromes(cw);
    if s.iter().all(|&x| x == 0) {
        return Ok(0);
    }
    let lam = berlekamp_massey(&s);
    let l = lam.len() - 1;
    if l > RS_T {
        return Err(RsError::Uncorrectable);
    }
    // Chien: Λ(α^{-d}) = 0 → ошибка в символе i = 543 − d (X = α^d)
    let mut positions: Vec<(usize, u16)> = Vec::new(); // (symbol idx, X)
    for d in 0..RS_N as i64 {
        let x_inv = alpha_pow(-d);
        if poly_eval(&lam, x_inv) == 0 {
            positions.push(((RS_N as i64 - 1 - d) as usize, alpha_pow(d)));
        }
    }
    if positions.len() != l {
        return Err(RsError::Uncorrectable);
    }
    // Ω(x) = (S(x)·Λ(x)) mod x^30
    let mut omega = vec![0u16; RS_PARITY];
    for i in 0..RS_PARITY {
        let mut acc = 0u16;
        for j in 0..=i {
            let li = i - j;
            if li < lam.len() {
                acc = add(acc, mul(s[j], lam[li]));
            }
        }
        omega[i] = acc;
    }
    // Λ'(x): производная в char 2 — сохраняются только нечётные степени
    // (i·Λ_i = Λ_i при i нечётном), с нулями на нечётных позициях результата
    let mut dlam = vec![0u16; lam.len().max(1)];
    for i in (1..lam.len()).step_by(2) {
        dlam[i - 1] = lam[i];
    }
    // Forney: Y = X · Ω(X⁻¹) / Λ'(X⁻¹)
    for &(idx, x) in &positions {
        let xi = inv(x);
        let num = mul(x, poly_eval(&omega, xi));
        let den = poly_eval(&dlam, xi);
        if den == 0 {
            return Err(RsError::Uncorrectable);
        }
        let y = mul(num, inv(den));
        cw[idx] = add(cw[idx], y);
    }
    // остаточная проверка (miscorrection guard)
    let s2 = syndromes(cw);
    if !s2.iter().all(|&v| v == 0) {
        return Err(RsError::Uncorrectable);
    }
    Ok(positions.len())
}

/// FEC-кодирование области данных (длина кратна REGION_UNIT_BYTES).
pub fn rs_encode_region(region: &[u8]) -> Result<Vec<u8>, RsError> {
    if region.is_empty() || region.len() % REGION_UNIT_BYTES != 0 {
        return Err(RsError::BadRegionLen);
    }
    let syms = pack_symbols(region);
    let num_cw = syms.len() / RS_K;
    let mut parity_bits: Vec<u8> = Vec::with_capacity(num_cw * RS_PARITY * SYMBOL_BITS);
    for cw_idx in 0..num_cw {
        let msg = &syms[cw_idx * RS_K..(cw_idx + 1) * RS_K];
        let par = encode_cw(msg);
        for &p in par.iter() {
            for b in (0..SYMBOL_BITS).rev() {
                parity_bits.push(((p >> b) & 1) as u8);
            }
        }
    }
    // упаковка parity-битов MSB-first в байты (num_cw чётно → ровно)
    let mut out = vec![0u8; parity_bits.len().div_ceil(8)];
    for (i, bit) in parity_bits.iter().enumerate() {
        out[i / 8] |= { *bit } << (7 - (i % 8));
    }
    Ok(out)
}

/// FEC-декодирование области данных; возвращает исправленную область.
pub fn rs_decode_region(region: &[u8], fec: &[u8]) -> Result<DecodeOutcome, RsError> {
    if region.is_empty() || region.len() % REGION_UNIT_BYTES != 0 {
        return Err(RsError::BadRegionLen);
    }
    let num_cw = region.len() * 8 / CW_BITS;
    let expect_fec = num_cw * RS_PARITY * SYMBOL_BITS / 8;
    if fec.len() != expect_fec {
        return Err(RsError::BadFecLen);
    }
    let syms = pack_symbols(region);
    // распаковка parity-битов
    let mut parity_syms: Vec<u16> = Vec::with_capacity(num_cw * RS_PARITY);
    for s in 0..num_cw * RS_PARITY {
        let mut v: u16 = 0;
        for b in 0..SYMBOL_BITS {
            let bit = s * SYMBOL_BITS + b;
            let on = (fec[bit / 8] >> (7 - (bit % 8))) & 1;
            v = (v << 1) | on as u16;
        }
        parity_syms.push(v);
    }
    let mut total_corrected = 0usize;
    let mut corrected_syms = syms;
    for cw_idx in 0..num_cw {
        let mut cw = [0u16; RS_N];
        cw[..RS_K].copy_from_slice(&corrected_syms[cw_idx * RS_K..(cw_idx + 1) * RS_K]);
        cw[RS_K..].copy_from_slice(&parity_syms[cw_idx * RS_PARITY..(cw_idx + 1) * RS_PARITY]);
        let fixed = decode_cw(&mut cw)?;
        total_corrected += fixed;
        corrected_syms[cw_idx * RS_K..(cw_idx + 1) * RS_K].copy_from_slice(&cw[..RS_K]);
    }
    Ok(DecodeOutcome {
        corrected_region: unpack_symbols(&corrected_syms, region.len()),
        corrected_symbols: total_corrected,
        used_fec: total_corrected > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf1024::tables;

    fn sample_region(k_units: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(k_units * REGION_UNIT_BYTES);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..(k_units * REGION_UNIT_BYTES) {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            v.push((x >> 16) as u8);
        }
        v
    }

    #[test]
    fn tables_sanity() {
        tables();
        assert_eq!(alpha_pow(0), 1);
    }

    #[test]
    fn encode_decode_clean() {
        let region = sample_region(1);
        let fec = rs_encode_region(&region).unwrap();
        assert_eq!(fec.len(), 2 * RS_PARITY * SYMBOL_BITS / 8); // 75 Б на 2 cw
        let out = rs_decode_region(&region, &fec).unwrap();
        assert_eq!(out.corrected_region, region);
        assert_eq!(out.corrected_symbols, 0);
        assert!(!out.used_fec);
    }

    #[test]
    fn corrects_up_to_15_symbol_errors_per_cw() {
        let region = sample_region(2); // 4 кодовых слова
        let fec = rs_encode_region(&region).unwrap();
        // детерминированные ошибки: 12 битовых позиций в области данных
        // каждого cw (≤12 символов) + 3 в parity (≤3 символа) — суммарно
        // ≤15 символов на кодовое слово = предел t=15
        let mut damaged_region = region.clone();
        let mut damaged_fec = fec.clone();
        for cw in 0..4 {
            for e in 0..12usize {
                let bit = cw * CW_BITS + e * 10 + 3; // по одной позиции в символе
                damaged_region[bit / 8] ^= 1 << (7 - (bit % 8));
            }
        }
        // плюс ошибки в parity-области (по 3 символа на cw)
        for cw in 0..4 {
            for e in 0..3usize {
                let bit = cw * RS_PARITY * SYMBOL_BITS + e * 10 + 1;
                damaged_fec[bit / 8] ^= 1 << (7 - (bit % 8));
            }
        }
        let out = rs_decode_region(&damaged_region, &damaged_fec).unwrap();
        assert_eq!(out.corrected_region, region, "все ошибки исправлены");
        assert!(out.used_fec);
        assert_eq!(out.corrected_symbols, 60, "12+3 символа на каждое из 4 cw");
    }

    #[test]
    fn detects_uncorrectable_16_errors() {
        let region = sample_region(1);
        let fec = rs_encode_region(&region).unwrap();
        let mut damaged = region.clone();
        // 16 полных символов (160 бит) в первом cw — за пределом t=15
        for e in 0..16usize {
            for b in 0..10 {
                let bit = e * 10 + b;
                damaged[bit / 8] ^= 1 << (7 - (bit % 8));
            }
        }
        assert_eq!(rs_decode_region(&damaged, &fec), Err(RsError::Uncorrectable));
    }

    #[test]
    fn bad_lengths_rejected() {
        let region = sample_region(1);
        let fec = rs_encode_region(&region).unwrap();
        assert_eq!(rs_encode_region(&region[..100]), Err(RsError::BadRegionLen));
        assert_eq!(rs_decode_region(&region[..100], &fec), Err(RsError::BadRegionLen));
        assert_eq!(rs_decode_region(&region, &fec[..10]), Err(RsError::BadFecLen));
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let data = sample_region(1);
        let syms = pack_symbols(&data);
        assert_eq!(syms.len(), data.len() * 8 / 10);
        assert_eq!(unpack_symbols(&syms, data.len()), data);
        // неполный последний символ
        let d2 = vec![0xAB; 3]; // 24 бита → 3 символа (последний с паддингом)
        let s2 = pack_symbols(&d2);
        assert_eq!(s2.len(), 3);
        assert_eq!(unpack_symbols(&s2, 3), d2);
    }
}
