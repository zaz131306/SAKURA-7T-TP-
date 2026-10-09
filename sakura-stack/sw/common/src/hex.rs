//! Hex-кодирование/декодирование.

pub fn encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("odd hex length");
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = nib(b[i]).ok_or("bad hex")?;
        let lo = nib(b[i + 1]).ok_or("bad hex")?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = vec![0x00, 0x0f, 0xff, 0xab];
        let s = encode(&b);
        assert_eq!(s, "000fffab");
        assert_eq!(decode(&s).unwrap(), b);
        assert!(decode("0").is_err());
        assert!(decode("zz").is_err());
    }
}
