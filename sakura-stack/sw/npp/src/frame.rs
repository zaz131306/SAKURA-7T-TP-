//! NPP-кадр v2.3 (§13.3, BC-1 детекция формата, BC-26 padding/FEC):
//!
//! ```text
//! | Preamble (8B) | SFD (1B) | Header (15B) | Payload (0–1500B)
//!   | Padding (var) | FEC (var) | CRC32 (4B) |
//! ```
//!
//! Header (15B, байты 9–23 кадра): Src(2) Dst(2) Seq(4) Type(1) Flags(1)
//! Length(2) Reserved(2) CRC8(1). CRC8 покрывает первые 14 байт заголовка.
//!
//! Flags (профиль ICD v2.3):
//! - bit7–6: версия (0b01 = v2.3; 0b00 = legacy-16 — детекция, не поддержка);
//! - bit0: FEC_PRESENT (RS(544,514) по выровненной области);
//! - bit1: PADDED (padding до границы FEC-codeword, BC-26);
//! - bit2: ENCRYPTED (payload — MGM-шифртекст сессии);
//! - bit3: FRAGMENT; bit5–4: reserved=0.
//!
//! Решения ICD по [TBD] §13.3:
//! - padding pattern = 0x00; padding включается в CRC32 (BC-26 MUST);
//! - область данных выравнивается до REGION_UNIT (1285 Б = 2 codeword);
//! - интерливинг FEC — последовательные кодовые слова (без интерливинга);
//! - максимальный размер кадра: 8+1+2570+150+4 = 2733 Б (payload 1500);
//! - CRC8: полином x⁸+x²+x+1 (0x07), init 0x00;
//! - при повреждении заголовка приёмник выполняет FEC-восстановление до
//!   валидации полей (иначе кадр отклоняется fail-secure).

use crate::msg::{MsgType, NppErrCode};
use crate::rs;

pub const PREAMBLE: [u8; 8] = [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA];
pub const SFD: u8 = 0xD5;
pub const HEADER_LEN: usize = 15;
pub const MAX_PAYLOAD: usize = 1500;
pub const CRC_LEN: usize = 4;
pub const FLAG_FEC: u8 = 0x01;
pub const FLAG_PADDED: u8 = 0x02;
pub const FLAG_ENCRYPTED: u8 = 0x04;
pub const FLAG_FRAGMENT: u8 = 0x08;
pub const VER_V23: u8 = 0x40; // bit7–6 = 0b01
pub const VER_MASK: u8 = 0xC0;
/// Байт региона на единицу выравнивания (2 кодовых слова) и FEC-байт на неё.
const UNIT_TOTAL: usize = rs::REGION_UNIT_BYTES + 75; // 1285 + 75
/// Максимальный размер кадра (решение ICD по [TBD] §13.3).
pub const MAX_FRAME_LEN: usize = 8 + 1 + 2 * rs::REGION_UNIT_BYTES + 150 + CRC_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Npp(NppErrCode),
    /// §13.8: NPP_PADDING_INVALID / NPP_FEC_UNCORRECTABLE / NPP_FRAME_TOO_LONG
    Common(sakura_common::ErrorCode),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub msg_type: MsgType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(src: u16, dst: u16, seq: u32, msg_type: MsgType, payload: Vec<u8>) -> Self {
        Frame { src, dst, seq, msg_type, flags: 0, payload }
    }
}

/// Результат декодирования: кадр + статус FEC + некритичные предупреждения
/// (§13.8 0x0011: WARNING для non-control).
#[derive(Clone, Debug)]
pub struct FrameDecodeOutcome {
    pub frame: Frame,
    pub fec_corrected_symbols: usize,
    pub warnings: Vec<sakura_common::ErrorCode>,
}

impl FrameDecodeOutcome {
    /// FEC применился для восстановления (учтено в журнале узла).
    pub fn used_fec_correction(&self) -> bool {
        self.fec_corrected_symbols > 0
    }
}

pub struct NppCodec {
    pub fec_enabled: bool,
}

impl Default for NppCodec {
    fn default() -> Self {
        Self::new(true)
    }
}

impl NppCodec {
    pub fn new(fec_enabled: bool) -> Self {
        NppCodec { fec_enabled }
    }

    /// Кодирование кадра в проводной формат.
    pub fn encode(&self, f: &Frame) -> Result<Vec<u8>, FrameError> {
        if f.payload.len() > MAX_PAYLOAD {
            return Err(FrameError::Common(sakura_common::ErrorCode::NppFrameTooLong));
        }
        let mut flags = (f.flags & (FLAG_ENCRYPTED | FLAG_FRAGMENT)) | VER_V23;
        let base_len = HEADER_LEN + f.payload.len();
        let mut region_len = base_len;
        if self.fec_enabled {
            let units = base_len.div_ceil(rs::REGION_UNIT_BYTES);
            region_len = units * rs::REGION_UNIT_BYTES;
            flags |= FLAG_FEC;
        }
        if region_len > base_len {
            flags |= FLAG_PADDED;
        }

        let mut hdr = [0u8; HEADER_LEN];
        hdr[0..2].copy_from_slice(&f.src.to_be_bytes());
        hdr[2..4].copy_from_slice(&f.dst.to_be_bytes());
        hdr[4..8].copy_from_slice(&f.seq.to_be_bytes());
        hdr[8] = f.msg_type as u8;
        hdr[9] = flags;
        hdr[10..12].copy_from_slice(&(f.payload.len() as u16).to_be_bytes());
        hdr[12..14].copy_from_slice(&[0, 0]); // Reserved
        hdr[14] = crc8(&hdr[..14]);

        let mut region = Vec::with_capacity(region_len);
        region.extend_from_slice(&hdr);
        region.extend_from_slice(&f.payload);
        region.resize(region_len, 0x00); // утверждённый padding pattern (BC-26)

        let fec = if self.fec_enabled {
            rs::rs_encode_region(&region).map_err(|_| FrameError::Npp(NppErrCode::InvalidFrame))?
        } else {
            Vec::new()
        };

        let mut wire = Vec::with_capacity(9 + region.len() + fec.len() + CRC_LEN);
        wire.extend_from_slice(&PREAMBLE);
        wire.push(SFD);
        wire.extend_from_slice(&region);
        wire.extend_from_slice(&fec);
        // CRC32 покрывает header+payload+padding (FEC-поле защищено
        // синдромами RS; решение ICD по покрытию CRC32)
        let crc = crc32_ieee(&region);
        wire.extend_from_slice(&crc.to_be_bytes());
        if wire.len() > MAX_FRAME_LEN {
            return Err(FrameError::Common(sakura_common::ErrorCode::NppFrameTooLong));
        }
        Ok(wire)
    }

    /// Декодирование (fail-secure, BC-1/BC-26):
    /// 1. структурные проверки (preamble/SFD/минимальная длина);
    /// 2. CRC8 заголовка валиден → обычный путь (детекция версии по Flags);
    /// 3. CRC8 невалиден → FEC-first восстановление (только v2.3-раскладка);
    ///    FEC не исправил → NPP_FEC_UNCORRECTABLE (CRITICAL, fail-secure);
    /// 4. валидация длины/padding/CRC32/FEC-status до передачи в control plane.
    pub fn decode(&self, wire: &[u8]) -> Result<FrameDecodeOutcome, FrameError> {
        if wire.len() < 9 + HEADER_LEN + CRC_LEN {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        if wire[..8] != PREAMBLE || wire[8] != SFD {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        let body_end = wire.len() - CRC_LEN;
        if body_end <= 9 {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        let crc_bytes = &wire[body_end..];

        let hdr_crc_ok = wire.len() >= 9 + HEADER_LEN && crc8(&wire[9..9 + 14]) == wire[9 + 14];
        let ver_bits = wire[9 + 9] & VER_MASK;

        if hdr_crc_ok && ver_bits != VER_V23 {
            // BC-1: версия в Flags приоритетна
            if ver_bits == 0 {
                // 0b00 — вероятный legacy-16: детекция по позиции CRC8 (байт 24)
                let legacy_ok = wire.len() > 25 && crc8(&wire[9..24]) == wire[24];
                let v23_ok = hdr_crc_ok;
                return Err(FrameError::Npp(if legacy_ok && !v23_ok {
                    NppErrCode::UnsupportedVersion
                } else {
                    // неоднозначность → отказ парсинга (fail-secure)
                    NppErrCode::InvalidFrame
                }));
            }
            return Err(FrameError::Npp(NppErrCode::UnsupportedVersion));
        }

        if hdr_crc_ok {
            let flags = wire[9 + 9];
            let length = u16::from_be_bytes([wire[9 + 10], wire[9 + 11]]) as usize;
            let fec_present = flags & FLAG_FEC != 0;
            let base_len = HEADER_LEN + length;
            let region_len = if fec_present {
                base_len.div_ceil(rs::REGION_UNIT_BYTES) * rs::REGION_UNIT_BYTES
            } else {
                base_len
            };
            let fec_len = if fec_present { (region_len / rs::REGION_UNIT_BYTES) * 75 } else { 0 };
            if wire.len() != 9 + region_len + fec_len + CRC_LEN {
                return Err(FrameError::Common(sakura_common::ErrorCode::NppFrameTooLong));
            }
            let region = &wire[9..9 + region_len];
            let fec = &wire[9 + region_len..9 + region_len + fec_len];
            self.finish(region, fec, crc_bytes)
        } else {
            // CRC8 заголовка повреждён: сначала — детекция legacy по байту 24
            if wire.len() > 25 && crc8(&wire[9..24]) == wire[24] {
                return Err(FrameError::Npp(NppErrCode::UnsupportedVersion));
            }
            // FEC-first: структура v2.3 — body кратен UNIT_TOTAL (1285+75)
            let body = &wire[9..body_end];
            if body.len() < UNIT_TOTAL || body.len() % UNIT_TOTAL != 0 {
                return Err(FrameError::Npp(NppErrCode::InvalidFrame));
            }
            let units = body.len() / UNIT_TOTAL;
            let region_len = units * rs::REGION_UNIT_BYTES;
            let region = &body[..region_len];
            let fec = &body[region_len..];
            // без заголовка класс трафика неизвестен → fail-secure: CRITICAL
            let outcome = rs::rs_decode_region(region, fec)
                .map_err(|_| FrameError::Common(sakura_common::ErrorCode::NppFecUncorrectable))?;
            let fec_slice_owned = fec.to_vec();
            self.finish_with_region(&outcome.corrected_region, &fec_slice_owned, crc_bytes, outcome.corrected_symbols)
        }
    }

    /// Валидация региона (FEC → CRC32 → padding → поля).
    fn finish(
        &self,
        region: &[u8],
        fec: &[u8],
        crc_bytes: &[u8],
    ) -> Result<FrameDecodeOutcome, FrameError> {
        let flags = region[9];
        let fec_present = flags & FLAG_FEC != 0;
        let (region_owned, corrected, warnings) = if fec_present && !fec.is_empty() {
            let msg_control = MsgType::from_u8(region[8]).map(|t| t.is_control()).unwrap_or(true);
            match rs::rs_decode_region(region, fec) {
                Ok(out) => {
                    let mut w = Vec::new();
                    if out.used_fec && !msg_control {
                        // §13.8 0x0011: WARNING для non-control (деградация)
                        w.push(sakura_common::ErrorCode::NppFecUncorrectable);
                    }
                    (out.corrected_region, out.corrected_symbols, w)
                }
                Err(_) => {
                    if msg_control {
                        // CRITICAL для control (§13.8 0x0011)
                        return Err(FrameError::Common(sakura_common::ErrorCode::NppFecUncorrectable));
                    }
                    // non-control: WARNING + попытка разобрать неисправленные данные
                    (
                        region.to_vec(),
                        0,
                        vec![sakura_common::ErrorCode::NppFecUncorrectable],
                    )
                }
            }
        } else {
            (region.to_vec(), 0, Vec::new())
        };
        self.finish_with_region(&region_owned, fec, crc_bytes, corrected)
            .map(|mut o| {
                o.warnings = warnings;
                o.fec_corrected_symbols = corrected;
                o
            })
    }

    fn finish_with_region(
        &self,
        region: &[u8],
        _fec: &[u8],
        crc_bytes: &[u8],
        corrected: usize,
    ) -> Result<FrameDecodeOutcome, FrameError> {
        if region.len() < HEADER_LEN {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        // CRC8 заголовка (повторно — после возможной FEC-коррекции)
        if crc8(&region[..14]) != region[14] {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        let src = u16::from_be_bytes([region[0], region[1]]);
        let dst = u16::from_be_bytes([region[2], region[3]]);
        let seq = u32::from_be_bytes([region[4], region[5], region[6], region[7]]);
        let msg_type =
            MsgType::from_u8(region[8]).ok_or(FrameError::Npp(NppErrCode::InvalidFrame))?;
        let flags = region[9];
        let length = u16::from_be_bytes([region[10], region[11]]) as usize;
        if region[12] != 0 || region[13] != 0 {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame)); // Reserved ≠ 0
        }
        if length > MAX_PAYLOAD {
            return Err(FrameError::Common(sakura_common::ErrorCode::NppFrameTooLong));
        }
        let base_len = HEADER_LEN + length;
        if region.len() < base_len {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        // CRC32 по (исправленному) региону (BC-26: padding включён в CRC32)
        let crc_calc = crc32_ieee(region);
        if crc_calc.to_be_bytes() != crc_bytes {
            return Err(FrameError::Npp(NppErrCode::InvalidFrame));
        }
        // padding validation (BC-26)
        let padded = flags & FLAG_PADDED != 0;
        if region.len() > base_len {
            if !padded {
                return Err(FrameError::Common(sakura_common::ErrorCode::NppPaddingInvalid));
            }
            if region[base_len..].iter().any(|&b| b != 0) {
                return Err(FrameError::Common(sakura_common::ErrorCode::NppPaddingInvalid));
            }
        } else if padded {
            return Err(FrameError::Common(sakura_common::ErrorCode::NppPaddingInvalid));
        }
        let payload = region[HEADER_LEN..base_len].to_vec();
        Ok(FrameDecodeOutcome {
            frame: Frame {
                src,
                dst,
                seq,
                msg_type,
                flags: flags & !(VER_MASK | FLAG_FEC | FLAG_PADDED),
                payload,
            },
            fec_corrected_symbols: corrected,
            warnings: Vec::new(),
        })
    }
}

// ---------------- фрагментация (§13.3: FLAG_FRAGMENT) ----------------

/// Максимальный размер полезной нагрузки одного фрагмента:
/// payload ≤1500 − 4 Б заголовок фрагмента.
pub const FRAG_UNIT: usize = 1400;

/// Разбиение сообщения на фрагменты (если ≤ FRAG_UNIT — один элемент
/// без фрагмент-заголовка, флаг FRAGMENT не выставляется).
pub fn split_fragments(payload: &[u8]) -> Vec<Vec<u8>> {
    if payload.len() <= FRAG_UNIT {
        return vec![payload.to_vec()];
    }
    let total: u16 = payload.len().div_ceil(FRAG_UNIT) as u16;
    payload
        .chunks(FRAG_UNIT)
        .enumerate()
        .map(|(idx, chunk)| {
            let mut frag = Vec::with_capacity(4 + chunk.len());
            frag.extend_from_slice(&total.to_be_bytes());
            frag.extend_from_slice(&(idx as u16).to_be_bytes());
            frag.extend_from_slice(chunk);
            frag
        })
        .collect()
}

/// Реассемблер фрагментов по (src, msg_type); FRAGMENT_TIMEOUT — 10 с
/// (§13.3: 0x0006).
#[derive(Default)]
pub struct FrameReassembler {
    pending: std::collections::BTreeMap<
        (u16, u8),
        (u16, std::collections::BTreeMap<u16, Vec<u8>>, u64),
    >,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassembleError {
    Malformed,
    Timeout,
}

impl FrameReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавить фрагмент; Ok(Some(full)) — сообщение собрано.
    pub fn push(
        &mut self,
        src: u16,
        mtype: u8,
        frag: &[u8],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, ReassembleError> {
        if frag.len() < 4 {
            return Err(ReassembleError::Malformed);
        }
        let total = u16::from_be_bytes([frag[0], frag[1]]);
        let idx = u16::from_be_bytes([frag[2], frag[3]]);
        if total == 0 || idx >= total {
            return Err(ReassembleError::Malformed);
        }
        let key = (src, mtype);
        let e = self.pending.entry(key).or_insert_with(|| (total, Default::default(), now_ms));
        if e.0 != total || now_ms.saturating_sub(e.2) > 10_000 {
            if e.0 != total && now_ms.saturating_sub(e.2) <= 10_000 {
                // новый total в середине сборки — прежняя сборка протухла?
                // fail-secure: сброс
            }
            *e = (total, Default::default(), now_ms);
        }
        e.1.insert(idx, frag[4..].to_vec());
        if e.1.len() == total as usize {
            let mut full = Vec::new();
            for i in 0..total {
                match e.1.get(&i) {
                    Some(p) => full.extend_from_slice(p),
                    None => {
                        self.pending.remove(&key);
                        return Err(ReassembleError::Timeout);
                    }
                }
            }
            self.pending.remove(&key);
            Ok(Some(full))
        } else {
            Ok(None)
        }
    }
}

/// CRC-8: полином x⁸+x²+x+1 (0x07), init 0x00 (профиль ICD).
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            let msb = crc & 0x80 != 0;
            crc <<= 1;
            if msb {
                crc ^= 0x07;
            }
        }
    }
    crc
}

/// CRC-32 IEEE 802.3 (reflected 0xEDB88320, init/final 0xFFFFFFFF).
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let lsb = crc & 1 != 0;
            crc >>= 1;
            if lsb {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_vectors() {
        // эталон IEEE 802.3: CRC32("123456789") = 0xCBF43926
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        // CRC-8/ATM (poly 0x07, init 0): "123456789" → 0xF4
        assert_eq!(crc8(b"123456789"), 0xF4);
    }

    #[test]
    fn frame_roundtrip_with_fec() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 77, MsgType::ControlCommand, b"command-payload".to_vec());
        let wire = codec.encode(&f).unwrap();
        assert_eq!(&wire[..8], &PREAMBLE);
        assert_eq!(wire[8], SFD);
        assert_eq!(wire.len(), 8 + 1 + 1285 + 75 + 4);
        let out = codec.decode(&wire).unwrap();
        assert_eq!(out.frame, f);
        assert_eq!(out.fec_corrected_symbols, 0);
        assert!(out.warnings.is_empty());
    }

    #[test]
    fn frame_roundtrip_no_fec() {
        let codec = NppCodec::new(false);
        let f = Frame::new(3, 4, 5, MsgType::Heartbeat, Vec::new());
        let wire = codec.encode(&f).unwrap();
        assert_eq!(wire.len(), 8 + 1 + 15 + 4);
        let out = codec.decode(&wire).unwrap();
        assert_eq!(out.frame, f);
    }

    #[test]
    fn fec_corrects_payload_errors() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 9, MsgType::SensorSummary, vec![0xAB; 200]);
        let mut wire = codec.encode(&f).unwrap();
        // 5 битовых ошибок в payload-части региона (за заголовком)
        for i in 0..5 {
            wire[9 + HEADER_LEN + i * 37] ^= 0x80 >> (i % 8);
        }
        let out = codec.decode(&wire).unwrap();
        assert_eq!(out.frame, f);
        assert!(out.used_fec_correction(), "FEC исправил ошибки");
    }

    #[test]
    fn fec_corrects_header_errors() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 9, MsgType::Status, b"hdr-test".to_vec());
        let mut wire = codec.encode(&f).unwrap();
        // порча заголовка (включая байт flags и CRC8) — FEC-first путь
        wire[9] ^= 0x01; // src
        wire[18] ^= 0x02; // flags
        wire[23] ^= 0x04; // CRC8
        let out = codec.decode(&wire).unwrap();
        assert_eq!(out.frame, f);
        assert!(out.used_fec_correction());
    }

    #[test]
    fn fec_uncorrectable_control_is_critical() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 9, MsgType::ControlCommand, vec![0xCD; 100]);
        let mut wire = codec.encode(&f).unwrap();
        // 16 полных символов в первом кодовом слове — за пределом t=15
        for e in 0..16usize {
            for b in 0..10 {
                let bit = e * 10 + b;
                let byte = 9 + bit / 8;
                wire[byte] ^= 1 << (7 - (bit % 8));
            }
        }
        assert_eq!(
            codec.decode(&wire).err(),
            Some(FrameError::Common(sakura_common::ErrorCode::NppFecUncorrectable))
        );
    }

    #[test]
    fn crc32_failure_invalid_frame() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 9, MsgType::Status, b"x".to_vec());
        let mut wire = codec.encode(&f).unwrap();
        // порча CRC32 (FEC его не покрывает)
        let n = wire.len();
        wire[n - 1] ^= 0xFF;
        // FEC-first не сработает (body не кратен UNIT_TOTAL? кратен — но
        // CRC8 заголовка цел → обычный путь → CRC32 mismatch)
        assert!(matches!(codec.decode(&wire), Err(FrameError::Npp(NppErrCode::InvalidFrame))));
    }

    #[test]
    fn reserved_field_error_corrected_by_fec() {
        // Единичная порча Reserved-байта — один символ RS: FEC обязан
        // восстановить кадр (демонстрация защиты заголовка)
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 9, MsgType::Status, b"y".to_vec());
        let mut wire = codec.encode(&f).unwrap();
        wire[9 + 12] = 7;
        let out = codec.decode(&wire).unwrap();
        assert_eq!(out.frame, f);
        assert!(out.used_fec_correction());
        // Без FEC та же порча → InvalidFrame (CRC32 не сходится)
        let codec_nf = NppCodec::new(false);
        let wire_nf = codec_nf.encode(&f).unwrap();
        let mut wire_nf2 = wire_nf.clone();
        wire_nf2[9 + 12] = 7;
        assert!(matches!(
            codec_nf.decode(&wire_nf2),
            Err(FrameError::Npp(NppErrCode::InvalidFrame))
        ));
    }

    #[test]
    fn reserved_nonzero_without_correction_rejected() {
        // Reserved ≠ 0 при валидных CRC (сформирован «вручную») — отказ
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 9, MsgType::Status, b"y".to_vec());
        let mut wire = codec.encode(&f).unwrap();
        wire[9 + 12] = 7;
        wire[9 + 14] = crc8(&wire[9..9 + 14]);
        // пересчитать FEC и CRC32 под изменённый регион — имитация
        let region_len = wire.len() - 9 - 75 - 4;
        let mut region = wire[9..9 + region_len].to_vec();
        region[12] = 7;
        let fec = rs::rs_encode_region(&region).unwrap();
        let mut wire2 = Vec::new();
        wire2.extend_from_slice(&wire[..9]);
        wire2.extend_from_slice(&region);
        wire2.extend_from_slice(&fec);
        wire2.extend_from_slice(&crc32_ieee(&region).to_be_bytes());
        assert_eq!(
            codec.decode(&wire2).err(),
            Some(FrameError::Npp(NppErrCode::InvalidFrame))
        );
    }

    #[test]
    fn bad_magic_and_short() {
        let codec = NppCodec::new(true);
        assert!(matches!(
            codec.decode(&[0u8; 30]),
            Err(FrameError::Npp(NppErrCode::InvalidFrame))
        ));
        let f = Frame::new(1, 2, 9, MsgType::Status, b"z".to_vec());
        let wire = codec.encode(&f).unwrap();
        assert!(matches!(
            codec.decode(&wire[..20]),
            Err(FrameError::Npp(NppErrCode::InvalidFrame))
        ));
    }

    #[test]
    fn legacy_format_fail_secure() {
        let codec = NppCodec::new(true);
        // конструируем «legacy-16»: ver bits = 00, CRC8 на байте 24
        let mut wire = Vec::new();
        wire.extend_from_slice(&PREAMBLE);
        wire.push(SFD);
        let mut hdr = [0u8; 16];
        hdr[0..2].copy_from_slice(&1u16.to_be_bytes());
        hdr[2..4].copy_from_slice(&2u16.to_be_bytes());
        hdr[4..8].copy_from_slice(&1u32.to_be_bytes());
        hdr[8] = MsgType::Status as u8;
        hdr[9] = 0x00; // ver bits 00
        hdr[10..12].copy_from_slice(&1u16.to_be_bytes());
        hdr[15] = crc8(&hdr[..15]);
        wire.extend_from_slice(&hdr);
        wire.push(b'q');
        wire.extend_from_slice(&crc32_ieee(&[&hdr[..], b"q"].concat()).to_be_bytes());
        assert_eq!(
            codec.decode(&wire).err(),
            Some(FrameError::Npp(NppErrCode::UnsupportedVersion))
        );
    }

    #[test]
    fn payload_too_long() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 1, MsgType::Status, vec![0u8; MAX_PAYLOAD + 1]);
        assert_eq!(
            codec.encode(&f).err(),
            Some(FrameError::Common(sakura_common::ErrorCode::NppFrameTooLong))
        );
    }

    #[test]
    fn max_payload_frame_within_limit() {
        let codec = NppCodec::new(true);
        let f = Frame::new(1, 2, 1, MsgType::AuditExportChunk, vec![0x5A; MAX_PAYLOAD]);
        let wire = codec.encode(&f).unwrap();
        assert!(wire.len() <= MAX_FRAME_LEN);
        let out = codec.decode(&wire).unwrap();
        assert_eq!(out.frame.payload.len(), MAX_PAYLOAD);
        // region = 2570 (2 единицы по 1285), FEC = 150
        assert_eq!(wire.len(), 8 + 1 + 2570 + 150 + 4);
        assert_eq!(wire.len(), MAX_FRAME_LEN);
    }
}
