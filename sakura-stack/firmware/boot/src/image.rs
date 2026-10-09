//! Формат образа прошивки (§22.1.2) и парсер заголовка по байтовым
//! смещениям (C-08: вместо #[repr(C, packed)] — явный парсер с полной
//! проверкой полей). Код соответствует ТП §22.1.3.

use crate::anchor::TrustAnchor;
use crate::cert::SignerCert;
use sakura_common::cbor::Cbor;

pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_SIGNED: u8 = 0x02;
pub const FLAG_ROLLBACK: u8 = 0x04;

pub const IMAGE_TYPE_BOOTLOADER: u8 = 0x01;
pub const IMAGE_TYPE_KERNEL: u8 = 0x02;
pub const IMAGE_TYPE_APP: u8 = 0x03;
pub const IMAGE_TYPE_MODEL: u8 = 0x04;

pub const ALG_STREEBOG_256: u8 = sakura_gost::ALG_STREEBOG_256;
pub const ALG_STREEBOG_512: u8 = sakura_gost::ALG_STREEBOG_512;
pub const ALG_GOST_PLUS_MLDSA65: u8 = sakura_gost::ALG_GOST_PLUS_MLDSA65;

// Фиксированная часть заголовка — 114 байт, смещения жёсткие (C-08):
const OFF_MAGIC: usize = 0; // 4 B
const OFF_VERSION: usize = 4; // 4 B
const OFF_MIN_HW_REV: usize = 8; // 2 B
const OFF_TYPE: usize = 10; // 1 B
const OFF_FLAGS: usize = 11; // 1 B
const OFF_SIZE: usize = 12; // 4 B
const OFF_HASH_ALG: usize = 16; // 1 B
const OFF_HASH: usize = 17; // 64 B (слот под Стрибог-512)
const OFF_SIGNER: usize = 81; // 16 B
const OFF_SIG_ALG: usize = 97; // 1 B
const OFF_ROLLBACK: usize = 98; // 4 B
const OFF_TIMESTAMP: usize = 102; // 8 B
const OFF_CERT_LEN: usize = 110; // 2 B
const OFF_SIG_LEN: usize = 112; // 2 B
pub const HEADER_LEN: usize = 114;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    HeaderTooShort,
    BadMagic,
    PayloadSizeMismatch,
    Truncated,
    Unsigned,
    HwRevMismatch,
    RollbackRejected,
    TimestampInvalid,
    UnsupportedHashAlg,
    HashMismatch,
    ChainInvalid,
    CertExpired,
    Revoked,
    GostSignatureInvalid,
    PqSignatureInvalid,
    SignatureTooShort,
    UnsupportedAlgorithm,
    CertMalformed,
    /// keyUsage сертификата не допускает подписание образов (§23.5).
    PolicyViolationUsage,
    /// Ошибка носителя/хранилища образов.
    Io,
    /// HSM attestation неуспешен (§13.16.1 HSM_ATTEST).
    HsmAttest,
    /// Ключ устройства отсутствует в HSM.
    KeyMissing,
    /// Key release policy check провален (§13.7).
    KeyReleasePolicy,
}

pub struct ImageHeader {
    pub version: u32,
    pub min_hw_rev: u16,
    pub image_type: u8,
    pub flags: u8,
    pub payload_size: u32,
    pub payload_hash_alg: u8,
    pub payload_hash: [u8; 64],
    pub signer_id: [u8; 16],
    pub signature_alg: u8,
    pub rollback_counter: u32,
    pub timestamp: u64,
}

pub struct ParsedImage<'a> {
    pub header: ImageHeader,
    pub payload: &'a [u8],
    pub cert_chain: &'a [u8],
    pub signature: &'a [u8],
}

impl ImageHeader {
    pub fn parse(buf: &[u8]) -> Result<ImageHeader, BootError> {
        if buf.len() < HEADER_LEN {
            return Err(BootError::HeaderTooShort);
        }
        if &buf[OFF_MAGIC..OFF_MAGIC + 4] != b"SAKU" {
            return Err(BootError::BadMagic);
        }
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&buf[OFF_HASH..OFF_HASH + 64]);
        let mut signer = [0u8; 16];
        signer.copy_from_slice(&buf[OFF_SIGNER..OFF_SIGNER + 16]);
        Ok(ImageHeader {
            version: u32::from_be_bytes(buf[OFF_VERSION..OFF_VERSION + 4].try_into().unwrap()),
            min_hw_rev: u16::from_be_bytes(buf[OFF_MIN_HW_REV..OFF_MIN_HW_REV + 2].try_into().unwrap()),
            image_type: buf[OFF_TYPE],
            flags: buf[OFF_FLAGS],
            payload_size: u32::from_be_bytes(buf[OFF_SIZE..OFF_SIZE + 4].try_into().unwrap()),
            payload_hash_alg: buf[OFF_HASH_ALG],
            payload_hash: hash,
            signer_id: signer,
            signature_alg: buf[OFF_SIG_ALG],
            rollback_counter: u32::from_be_bytes(buf[OFF_ROLLBACK..OFF_ROLLBACK + 4].try_into().unwrap()),
            timestamp: u64::from_be_bytes(buf[OFF_TIMESTAMP..OFF_TIMESTAMP + 8].try_into().unwrap()),
        })
    }

    /// Заголовок фиксированной части (114 Б) — входит в подписываемые данные.
    pub fn header_bytes(&self, cert_len: u16, sig_len: u16) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(b"SAKU");
        b[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&self.version.to_be_bytes());
        b[OFF_MIN_HW_REV..OFF_MIN_HW_REV + 2].copy_from_slice(&self.min_hw_rev.to_be_bytes());
        b[OFF_TYPE] = self.image_type;
        b[OFF_FLAGS] = self.flags;
        b[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&self.payload_size.to_be_bytes());
        b[OFF_HASH_ALG] = self.payload_hash_alg;
        b[OFF_HASH..OFF_HASH + 64].copy_from_slice(&self.payload_hash);
        b[OFF_SIGNER..OFF_SIGNER + 16].copy_from_slice(&self.signer_id);
        b[OFF_SIG_ALG] = self.signature_alg;
        b[OFF_ROLLBACK..OFF_ROLLBACK + 4].copy_from_slice(&self.rollback_counter.to_be_bytes());
        b[OFF_TIMESTAMP..OFF_TIMESTAMP + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        b[OFF_CERT_LEN..OFF_CERT_LEN + 2].copy_from_slice(&cert_len.to_be_bytes());
        b[OFF_SIG_LEN..OFF_SIG_LEN + 2].copy_from_slice(&sig_len.to_be_bytes());
        b
    }
}

pub fn parse_image(buf: &[u8]) -> Result<ParsedImage<'_>, BootError> {
    let header = ImageHeader::parse(buf)?;
    let payload = buf
        .get(HEADER_LEN..HEADER_LEN + header.payload_size as usize)
        .ok_or(BootError::PayloadSizeMismatch)?;
    // cert_len/sig_len — из подписанной фиксированной части заголовка
    // (смещения 110/112, C-08): дублирование длин в теле запрещено.
    let cert_len =
        u16::from_be_bytes(buf[OFF_CERT_LEN..OFF_CERT_LEN + 2].try_into().unwrap()) as usize;
    let sig_len =
        u16::from_be_bytes(buf[OFF_SIG_LEN..OFF_SIG_LEN + 2].try_into().unwrap()) as usize;
    let off = HEADER_LEN + header.payload_size as usize;
    let cert_chain = buf.get(off..off + cert_len).ok_or(BootError::Truncated)?;
    let off2 = off + cert_len;
    let signature = buf.get(off2..off2 + sig_len).ok_or(BootError::Truncated)?;
    if buf.len() != off2 + sig_len {
        return Err(BootError::Truncated); // хвост вне формата — fail-secure
    }
    Ok(ParsedImage { header, payload, cert_chain, signature })
}

/// Данные, покрываемые подписью образа: заголовок(114) || payload.
pub fn image_sign_data(header114: &[u8; HEADER_LEN], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len());
    v.extend_from_slice(header114);
    v.extend_from_slice(payload);
    v
}

pub struct DeviceState {
    pub hw_rev: u16,
    pub now_s: Option<u64>,
    /// min_versions[image_type-1] — активные rollback-счётчики (BC-24).
    pub min_versions: [u32; 4],
}

impl ParsedImage<'_> {
    pub fn verify(&self, anchor: &TrustAnchor, device: &DeviceState) -> Result<(), BootError> {
        let h = &self.header;
        if h.flags & FLAG_SIGNED == 0 {
            return Err(BootError::Unsigned);
        }
        if h.payload_size as usize != self.payload.len() {
            return Err(BootError::PayloadSizeMismatch);
        }
        if !(1..=4).contains(&h.image_type) {
            return Err(BootError::UnsupportedAlgorithm);
        }
        if h.min_hw_rev > device.hw_rev {
            return Err(BootError::HwRevMismatch);
        }
        let idx = (h.image_type.wrapping_sub(1)) as usize;
        if h.rollback_counter < device.min_versions[idx] {
            return Err(BootError::RollbackRejected);
        }
        if let Some(now) = device.now_s {
            if h.timestamp > now + 60 {
                return Err(BootError::TimestampInvalid);
            }
        }
        let expected = match h.payload_hash_alg {
            ALG_STREEBOG_256 => &h.payload_hash[..32],
            ALG_STREEBOG_512 => &h.payload_hash[..],
            _ => return Err(BootError::UnsupportedHashAlg),
        };
        // цепочка сертификатов из поля cert_chain (CBOR array of SignerCert)
        let chain = cert_chain_from_cbor(self.cert_chain)?;
        // 1) проверка хэша payload; 2) цепочка/CRL/время; 3) подпись по
        // заголовок||payload (полное покрытие, §22.1.4)
        anchor.verify_hybrid(
            self.payload,
            expected,
            h.payload_hash_alg,
            &chain,
            &h.signer_id,
            &h.header_bytes(self.cert_chain.len() as u16, self.signature.len() as u16),
            self.signature,
            h.signature_alg,
            device.now_s,
        )
    }

    /// Проверка подписи заголовка+payload (полное покрытие подписи).
    pub fn verify_signature_full(&self, anchor: &TrustAnchor, now_s: Option<u64>) -> Result<(), BootError> {
        let cert_len = self.cert_chain.len() as u16;
        let sig_len = self.signature.len() as u16;
        let hdr = self.header.header_bytes(cert_len, sig_len);
        let data = image_sign_data(&hdr, self.payload);
        let chain = cert_chain_from_cbor(self.cert_chain)?;
        anchor.verify_message(&data, &chain, &self.header.signer_id, self.signature, self.header.signature_alg, now_s)
    }
}

pub fn cert_chain_from_cbor(bytes: &[u8]) -> Result<Vec<SignerCert>, BootError> {
    let doc = Cbor::from_slice(bytes).map_err(|_| BootError::CertMalformed)?;
    let arr = doc.as_array().ok_or(BootError::CertMalformed)?;
    let mut out = Vec::with_capacity(arr.len());
    for c in arr {
        out.push(SignerCert::from_cbor(c).ok_or(BootError::CertMalformed)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> Vec<u8> {
        let payload = b"kernel-binary".to_vec();
        let mut buf = Vec::new();
        let h = ImageHeader {
            version: 7,
            min_hw_rev: 2,
            image_type: IMAGE_TYPE_KERNEL,
            flags: FLAG_SIGNED | FLAG_ROLLBACK,
            payload_size: payload.len() as u32,
            payload_hash_alg: ALG_STREEBOG_256,
            payload_hash: {
                let mut x = [0u8; 64];
                x[..32].copy_from_slice(&sakura_gost::hash::streebog256(&payload));
                x
            },
            signer_id: [9u8; 16],
            signature_alg: ALG_GOST_PLUS_MLDSA65,
            rollback_counter: 5,
            timestamp: 1_760_000_000,
        };
        let hdr = h.header_bytes(4, 6);
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(b"cert");
        buf.extend_from_slice(b"SIGNAT");
        buf
    }

    #[test]
    fn parse_roundtrip() {
        let buf = sample_image();
        let img = parse_image(&buf).unwrap();
        assert_eq!(img.header.version, 7);
        assert_eq!(img.header.min_hw_rev, 2);
        assert_eq!(img.header.image_type, IMAGE_TYPE_KERNEL);
        assert_eq!(img.header.flags, FLAG_SIGNED | FLAG_ROLLBACK);
        assert_eq!(img.header.payload_size, 13);
        assert_eq!(img.payload, b"kernel-binary");
        assert_eq!(img.cert_chain, b"cert");
        assert_eq!(img.signature, b"SIGNAT");
        assert_eq!(img.header.rollback_counter, 5);
        assert_eq!(img.header.timestamp, 1_760_000_000);
        assert_eq!(img.header.signer_id, [9u8; 16]);
    }

    #[test]
    fn parse_errors() {
        let buf = sample_image();
        // короткий буфер
        assert!(matches!(parse_image(&buf[..100]), Err(BootError::HeaderTooShort)));
        // bad magic
        let mut bad = buf.clone();
        bad[0] = b'X';
        assert!(matches!(parse_image(&bad), Err(BootError::BadMagic)));
        // payload size mismatch (обрезан)
        let mut bad2 = buf.clone();
        bad2[15] = 0xFF; // payload_size → огромный
        assert!(matches!(parse_image(&bad2), Err(BootError::PayloadSizeMismatch)));
        // truncated cert
        let bad3 = &buf[..HEADER_LEN + 13 + 2 + 2];
        assert!(matches!(parse_image(bad3), Err(BootError::Truncated)));
    }

    #[test]
    fn unsigned_rejected() {
        let mut buf = sample_image();
        buf[OFF_FLAGS] = 0; // снять FLAG_SIGNED
        let img = parse_image(&buf).unwrap();
        let anchor = TrustAnchor::empty_for_test();
        let dev = DeviceState { hw_rev: 3, now_s: None, min_versions: [0; 4] };
        assert_eq!(img.verify(&anchor, &dev), Err(BootError::Unsigned));
    }
}
