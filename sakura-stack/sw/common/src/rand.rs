//! Доступ к OS-энтропии (TRNG-заглушка хост-платформы; §23.8: production —
//! сертифицированный ГПСЧ, здесь — getrandom/ОС-источник с risk acceptance
//! для SIL-контура).

/// Заполнить буфер случайными байтами из ОС-источника.
pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS entropy unavailable");
}

pub fn u64_random() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

pub fn u32_random() -> u32 {
    let mut b = [0u8; 4];
    fill(&mut b);
    u32::from_le_bytes(b)
}

/// Вектор случайных байт заданной длины.
pub fn vec_random(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_differs() {
        let a = vec_random(32);
        let b = vec_random(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
}
