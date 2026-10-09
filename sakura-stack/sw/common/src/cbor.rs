//! Детерминированный canonical CBOR (RFC 8949, §4.2.1 Core Deterministic
//! Encoding Requirements) — нормативная сериализация DM-1 (§13.18.1):
//!
//! - предпочтительная (минимальная) длина заголовка целых;
//! - упорядочение ключей map: сначала по длине кодирования ключа,
//!   при равенстве — побайтово (length-first byte-order lexicographic);
//! - только определённые (definite) длины;
//! - строгий декодер отвергает неканонические кодировки.
//!
//! JSON — только debug (DM-1): данный модуль является единственной
//! нормативной сериализацией.

use std::fmt;

/// Значение CBOR. Числа с плавающей точкой намеренно отсутствуют:
/// детерминизм платформы требует целочисленных/fixed-point представлений.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cbor {
    UInt(u64),
    /// Отрицательное целое (хранится как |v|-1 major type 1; v < 0).
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    /// Map: пары хранятся отсортированными по каноническому порядку ключей.
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    Null,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    Truncated,
    NonCanonicalHead,
    IndefiniteLength,
    UnsortedMapKeys,
    DuplicateMapKey,
    FloatNotSupported,
    UnknownSimple(u8),
    NestingTooDeep,
    Reserved(u8),
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CborError {}

const MT_UINT: u8 = 0;
const MT_NINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_TEXT: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_TAG: u8 = 6;
const MT_SIMPLE: u8 = 7;

pub const SIMPLE_FALSE: u8 = 20;
pub const SIMPLE_TRUE: u8 = 21;
pub const SIMPLE_NULL: u8 = 22;

const MAX_DEPTH: usize = 64;

impl Cbor {
    // ---- конструкторы ----

    pub fn text(s: impl Into<String>) -> Self {
        Cbor::Text(s.into())
    }
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Cbor::Bytes(b.into())
    }
    pub fn array(v: Vec<Cbor>) -> Self {
        Cbor::Array(v)
    }
    pub fn int(v: i64) -> Self {
        if v >= 0 {
            Cbor::UInt(v as u64)
        } else {
            Cbor::NInt(v)
        }
    }
    /// Map из итератора пар; автоматически сортируется по каноническому
    /// порядку ключей RFC 8949 §4.2.1. Паника при дубликате ключа.
    pub fn map<I: IntoIterator<Item = (Cbor, Cbor)>>(items: I) -> Self {
        let mut v: Vec<(Cbor, Cbor)> = items.into_iter().collect();
        for e in &v {
            e.0.encode_key();
        }
        v.sort_by(|a, b| key_cmp(&a.0, &b.0));
        for w in v.windows(2) {
            assert!(!key_eq(&w[0].0, &w[1].0), "duplicate CBOR map key");
        }
        Cbor::Map(v)
    }
    /// Пустая map — без сортировки.
    pub fn empty_map() -> Self {
        Cbor::Map(Vec::new())
    }

    // ---- кодирование ----

    fn encode_key(&self) {
        // Проверка, что значение допустимо как ключ (не float).
        match self {
            Cbor::Null | Cbor::Bool(_) | Cbor::UInt(_) | Cbor::NInt(_) => {}
            _ => {}
        }
    }

    /// Каноническое кодирование в новый буфер.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out, 0);
        out
    }

    fn encode(&self, out: &mut Vec<u8>, depth: usize) {
        assert!(depth < MAX_DEPTH, "CBOR nesting too deep");
        match self {
            Cbor::UInt(v) => write_head(out, MT_UINT, *v),
            Cbor::NInt(v) => {
                assert!(*v < 0);
                // major 1 argument = -1 - v
                let arg = (-(v + 1)) as u64;
                write_head(out, MT_NINT, arg);
            }
            Cbor::Bytes(b) => {
                write_head(out, MT_BYTES, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Text(t) => {
                let b = t.as_bytes();
                write_head(out, MT_TEXT, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Array(items) => {
                write_head(out, MT_ARRAY, items.len() as u64);
                for it in items {
                    it.encode(out, depth + 1);
                }
            }
            Cbor::Map(items) => {
                write_head(out, MT_MAP, items.len() as u64);
                for (k, v) in items {
                    k.encode(out, depth + 1);
                    v.encode(out, depth + 1);
                }
            }
            Cbor::Tag(t, v) => {
                write_head(out, MT_TAG, *t);
                v.encode(out, depth + 1);
            }
            Cbor::Bool(b) => out.push(if *b { SIMPLE_TRUE } else { SIMPLE_FALSE } | (MT_SIMPLE << 5)),
            Cbor::Null => out.push((MT_SIMPLE << 5) | SIMPLE_NULL),
        }
    }

    // ---- декодирование (строгое) ----

    /// Строгий парсер: отвергает неканонические заголовки, indefinite-длины,
    /// несортированные/дублирующиеся ключи map, float, лишние байты в конце.
    pub fn from_slice(input: &[u8]) -> Result<Self, CborError> {
        let (v, rest) = Self::decode(input, 0)?;
        if !rest.is_empty() {
            return Err(CborError::Truncated); // trailing data
        }
        Ok(v)
    }

    /// Парсер одного значения; возвращает остаток буфера.
    pub fn decode(input: &[u8], depth: usize) -> Result<(Self, &[u8]), CborError> {
        if depth >= MAX_DEPTH {
            return Err(CborError::NestingTooDeep);
        }
        if input.is_empty() {
            return Err(CborError::Truncated);
        }
        let ib = input[0];
        let mt = ib >> 5;
        let ai = ib & 0x1f;
        if (28..=30).contains(&ai) {
            return Err(CborError::Reserved(ai));
        }
        let (arg, mut rest) = read_arg(input, ai)?;
        match mt {
            MT_UINT => Ok((Cbor::UInt(arg), rest)),
            MT_NINT => {
                let v = -(arg as i64) - 1;
                Ok((Cbor::NInt(v), rest))
            }
            MT_BYTES => {
                if ai == 31 {
                    return Err(CborError::IndefiniteLength);
                }
                let n = arg as usize;
                if rest.len() < n {
                    return Err(CborError::Truncated);
                }
                let (b, r) = rest.split_at(n);
                rest = r;
                Ok((Cbor::Bytes(b.to_vec()), rest))
            }
            MT_TEXT => {
                if ai == 31 {
                    return Err(CborError::IndefiniteLength);
                }
                let n = arg as usize;
                if rest.len() < n {
                    return Err(CborError::Truncated);
                }
                let (b, r) = rest.split_at(n);
                let s = std::str::from_utf8(b).map_err(|_| CborError::Truncated)?;
                rest = r;
                Ok((Cbor::Text(s.to_owned()), rest))
            }
            MT_ARRAY => {
                if ai == 31 {
                    return Err(CborError::IndefiniteLength);
                }
                let n = arg as usize;
                let mut items = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    let (v, r) = Self::decode(rest, depth + 1)?;
                    items.push(v);
                    rest = r;
                }
                Ok((Cbor::Array(items), rest))
            }
            MT_MAP => {
                if ai == 31 {
                    return Err(CborError::IndefiniteLength);
                }
                let n = arg as usize;
                let mut items: Vec<(Cbor, Cbor)> = Vec::with_capacity(n.min(4096));
                let mut prev_key: Option<Cbor> = None;
                for _ in 0..n {
                    let (k, r) = Self::decode(rest, depth + 1)?;
                    rest = r;
                    let (v, r) = Self::decode(rest, depth + 1)?;
                    rest = r;
                    if let Some(pk) = &prev_key {
                        match key_cmp(pk, &k) {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => return Err(CborError::DuplicateMapKey),
                            std::cmp::Ordering::Greater => return Err(CborError::UnsortedMapKeys),
                        }
                    }
                    prev_key = Some(k.clone());
                    items.push((k, v));
                }
                Ok((Cbor::Map(items), rest))
            }
            MT_TAG => {
                let (v, r) = Self::decode(rest, depth + 1)?;
                Ok((Cbor::Tag(arg, Box::new(v)), r))
            }
            MT_SIMPLE => match ai {
                20 => Ok((Cbor::Bool(false), rest)),
                21 => Ok((Cbor::Bool(true), rest)),
                22 => Ok((Cbor::Null, rest)),
                23 => Err(CborError::UnknownSimple(23)), // undefined
                25 | 26 => Err(CborError::FloatNotSupported),
                27 => Err(CborError::FloatNotSupported),
                31 => Err(CborError::IndefiniteLength), // break
                other => Err(CborError::UnknownSimple(other)),
            },
            _ => unreachable!(),
        }
    }

    // ---- доступ к полям ----

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Cbor::UInt(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Cbor::UInt(v) => i64::try_from(*v).ok(),
            Cbor::NInt(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(t) => Some(t),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Cbor]> {
        match self {
            Cbor::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Cbor::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /// Поиск значения по текстовому ключу в Map.
    pub fn get(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(items) => items
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Запись заголовка (major type, argument) минимальной длиной.
fn write_head(out: &mut Vec<u8>, mt: u8, arg: u64) {
    let b = mt << 5;
    if arg < 24 {
        out.push(b | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(b | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(b | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(b | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(b | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Чтение argument'а; проверяет минимальность кодирования (canonical).
fn read_arg(input: &[u8], ai: u8) -> Result<(u64, &[u8]), CborError> {
    let rest = &input[1..];
    match ai {
        0..=23 => Ok((ai as u64, rest)),
        24 => {
            if rest.is_empty() {
                return Err(CborError::Truncated);
            }
            let v = rest[0] as u64;
            if v < 24 {
                return Err(CborError::NonCanonicalHead);
            }
            Ok((v, &rest[1..]))
        }
        25 => {
            if rest.len() < 2 {
                return Err(CborError::Truncated);
            }
            let v = u16::from_be_bytes([rest[0], rest[1]]) as u64;
            if v <= u8::MAX as u64 {
                return Err(CborError::NonCanonicalHead);
            }
            Ok((v, &rest[2..]))
        }
        26 => {
            if rest.len() < 4 {
                return Err(CborError::Truncated);
            }
            let v = u32::from_be_bytes(rest[..4].try_into().unwrap()) as u64;
            if v <= u16::MAX as u64 {
                return Err(CborError::NonCanonicalHead);
            }
            Ok((v, &rest[4..]))
        }
        27 => {
            if rest.len() < 8 {
                return Err(CborError::Truncated);
            }
            let v = u64::from_be_bytes(rest[..8].try_into().unwrap());
            if v <= u32::MAX as u64 {
                return Err(CborError::NonCanonicalHead);
            }
            Ok((v, &rest[8..]))
        }
        31 => Ok((0, rest)), // indefinite / break — обрабатывается вызывающим
        _ => Err(CborError::Reserved(ai)),
    }
}

fn key_cmp(a: &Cbor, b: &Cbor) -> std::cmp::Ordering {
    // RFC 8949 §4.2.1: length-first byte-order lexicographic по кодированным ключам.
    let ka = a.to_vec();
    let kb = b.to_vec();
    ka.len().cmp(&kb.len()).then_with(|| ka.cmp(&kb))
}

fn key_eq(a: &Cbor, b: &Cbor) -> bool {
    a.to_vec() == b.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_head_minimal() {
        assert_eq!(Cbor::UInt(0).to_vec(), vec![0x00]);
        assert_eq!(Cbor::UInt(23).to_vec(), vec![0x17]);
        assert_eq!(Cbor::UInt(24).to_vec(), vec![0x18, 0x18]);
        assert_eq!(Cbor::UInt(255).to_vec(), vec![0x18, 0xff]);
        assert_eq!(Cbor::UInt(256).to_vec(), vec![0x19, 0x01, 0x00]);
        assert_eq!(Cbor::UInt(1_000_000).to_vec(), vec![0x1a, 0x00, 0x0f, 0x42, 0x40]);
        assert_eq!(
            Cbor::UInt(1_000_000_000_000).to_vec(),
            vec![0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]
        );
        assert_eq!(Cbor::int(-1).to_vec(), vec![0x20]);
        assert_eq!(Cbor::int(-1000).to_vec(), vec![0x39, 0x03, 0xe7]);
    }

    #[test]
    fn roundtrip() {
        let v = Cbor::map(vec![
            (Cbor::text("b"), Cbor::UInt(2)),
            (Cbor::text("aa"), Cbor::bytes(vec![1, 2, 3])),
            (Cbor::text("c"), Cbor::array(vec![Cbor::Bool(true), Cbor::Null, Cbor::int(-7)])),
            (Cbor::UInt(1), Cbor::text("x")),
        ]);
        let enc = v.to_vec();
        let dec = Cbor::from_slice(&enc).unwrap();
        assert_eq!(v, dec);
        // повторное кодирование byte-identical (требование DM-1 §13.18.3 п.2)
        assert_eq!(enc, dec.to_vec());
    }

    #[test]
    fn map_keys_sorted_length_first() {
        let m = Cbor::map(vec![
            (Cbor::text("zzzz"), Cbor::UInt(1)),
            (Cbor::text("a"), Cbor::UInt(2)),
            (Cbor::text("bb"), Cbor::UInt(3)),
        ]);
        let enc = m.to_vec();
        // порядок: "a" (len1), "bb" (len2), "zzzz" (len4)
        assert_eq!(enc[0], 0xa3);
        assert_eq!(&enc[1..3], b"\x61a");
        let dec = Cbor::from_slice(&enc).unwrap();
        if let Cbor::Map(items) = dec {
            assert_eq!(items[0].0.as_text(), Some("a"));
            assert_eq!(items[1].0.as_text(), Some("bb"));
            assert_eq!(items[2].0.as_text(), Some("zzzz"));
        } else {
            panic!("not a map");
        }
    }

    #[test]
    fn rejects_unsorted_and_noncanonical() {
        // несортированные ключи: "zzzz" перед "a"
        let mut bad = vec![0xa2, 0x64];
        bad.extend_from_slice(b"zzzz");
        bad.push(0x01);
        bad.extend_from_slice(b"\x61a");
        bad.push(0x02);
        assert_eq!(Cbor::from_slice(&bad), Err(CborError::UnsortedMapKeys));
        // неканонический заголовок: 24 в 2-байтовом формате
        assert_eq!(Cbor::from_slice(&[0x18, 0x05]), Err(CborError::NonCanonicalHead));
        // indefinite array
        assert_eq!(Cbor::from_slice(&[0x9f, 0x01, 0xff]), Err(CborError::IndefiniteLength));
        // float
        assert_eq!(
            Cbor::from_slice(&[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0]),
            Err(CborError::FloatNotSupported)
        );
        // trailing bytes
        assert_eq!(Cbor::from_slice(&[0x01, 0x02]), Err(CborError::Truncated));
    }

    /// Контрольный пример DM-1 §13.18.3: AuditRecord map(12), canonical.
    #[test]
    fn audit_record_example_13_18_3() {
        let rec = Cbor::map(vec![
            (Cbor::text("seq"), Cbor::UInt(1)),
            (Cbor::text("result"), Cbor::text("OK")),
            (Cbor::text("node_id"), Cbor::bytes((1u16..=16u16).map(|i| i as u8).collect::<Vec<_>>())),
            (
                Cbor::text("actor_id"),
                Cbor::bytes(hex_bytes("112233445566778899aabbccddeeff00")),
            ),
            (Cbor::text("hash_prev"), Cbor::bytes(vec![0u8; 32])),
            (Cbor::text("hash_self"), Cbor::bytes(hex_bytes("9f86d081884c7d65"))),
            (
                Cbor::text("object_id"),
                Cbor::bytes(hex_bytes("aabbccddeeff00112233445566778899")),
            ),
            (Cbor::text("key_epoch"), Cbor::UInt(1)),
            (Cbor::text("signature"), Cbor::bytes(vec![0xAB; 3373])),
            (Cbor::text("event_type"), Cbor::text("KEY_OPERATION")),
            (Cbor::text("session_id"), Cbor::UInt(42)),
            (Cbor::text("timestamp_s"), Cbor::UInt(1_760_000_000)),
        ]);
        let enc = rec.to_vec();
        // map(12)
        assert_eq!(enc[0], 0xAC);
        // "seq": 1  → 63 73 65 71 01
        assert_eq!(&enc[1..6], b"\x63seq\x01");
        // "result": "OK" → 66 "result" 62 "OK"
        assert_eq!(enc[6], 0x66);
        assert_eq!(&enc[7..13], b"result");
        assert_eq!(enc[13], 0x62);
        assert_eq!(&enc[14..16], b"OK");
        // node_id: bstr(16) 0x50 01..10
        let j = 16;
        assert_eq!(enc[j], 0x67); // text(7) "node_id"
        assert_eq!(&enc[j + 1..j + 8], b"node_id");
        assert_eq!(enc[j + 8], 0x50);
        assert_eq!(&enc[j + 9..j + 25], (1..=16u8).collect::<Vec<u8>>());
        // session_id: 42 → 18 2A ; timestamp: 1A 68 E7 78 00
        let tail_sig = find_sub(&enc, b"\x6asession_id\x18\x2a");
        assert!(tail_sig.is_some(), "session_id encoding 18 2A");
        let tail_ts = find_sub(&enc, b"\x6btimestamp_s\x1a\x68\xe7\x78\x00");
        assert!(tail_ts.is_some(), "timestamp_s 1A 68E77800");
        // signature: 0x59 0x0D 0x2D (3373)
        let sig_head = find_sub(&enc, b"\x69signature\x59\x0d\x2d");
        assert!(sig_head.is_some(), "signature bstr(3373) 59 0D2D");
        // строгий roundtrip
        let dec = Cbor::from_slice(&enc).unwrap();
        assert_eq!(dec, rec);
        assert_eq!(dec.to_vec(), enc);
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        crate::hex::decode(s).unwrap()
    }

    fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }
}
