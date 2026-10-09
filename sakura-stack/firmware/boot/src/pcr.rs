//! Measured boot: PCR-банк (§22.16, TCG-семантика extend).

use sakura_common::cbor::Cbor;
use sakura_gost::hash::streebog256;

pub const PCR_COUNT: usize = 16;

// Распределение PCR (§22.16):
pub const PCR_ROM_PBL_CONFIG: u8 = 0;
pub const PCR_SBL: u8 = 1;
pub const PCR_KERNEL: u8 = 2;
pub const PCR_INITRD_DRIVERS: u8 = 3;
pub const PCR_CONTROL_SERVICES: u8 = 4;
pub const PCR_CRYPTO_POLICY: u8 = 5;
pub const PCR_HSM_STATUS: u8 = 6;
pub const PCR_SECURE_BOOT_STATE: u8 = 7;
pub const PCR_NETWORK_POLICY: u8 = 8;
pub const PCR_AI_RUNTIME: u8 = 9; // T8 attestation
pub const PCR_MODELS: u8 = 10; // T8 attestation
pub const PCR_CONFIGURATION: u8 = 11;
pub const PCR_RECOVERY_MODE: u8 = 12;
pub const PCR_APP_DEBUG: u8 = 13; // 13–15: application/debug

#[derive(Clone, Debug)]
pub struct PcrBank {
    pcrs: [[u8; 32]; PCR_COUNT],
    /// Журнал измерений (measured boot log, §22.14).
    log: Vec<(u8, Vec<u8>)>,
}

impl Default for PcrBank {
    fn default() -> Self {
        Self::new()
    }
}

impl PcrBank {
    pub fn new() -> Self {
        PcrBank { pcrs: [[0u8; 32]; PCR_COUNT], log: Vec::new() }
    }

    /// PCR[i] = Стрибог-256(PCR[i] || data) — TCG-семантика.
    pub fn extend(&mut self, idx: u8, data: &[u8]) {
        assert!((idx as usize) < PCR_COUNT);
        let mut buf = Vec::with_capacity(32 + data.len());
        buf.extend_from_slice(&self.pcrs[idx as usize]);
        buf.extend_from_slice(data);
        self.pcrs[idx as usize] = streebog256(&buf);
        self.log.push((idx, streebog256(data).to_vec()));
    }

    pub fn get(&self, idx: u8) -> [u8; 32] {
        assert!((idx as usize) < PCR_COUNT);
        self.pcrs[idx as usize]
    }

    pub fn log(&self) -> &[(u8, Vec<u8>)] {
        &self.log
    }

    /// pcr_map DM-1: map<uint, bstr(32)>.
    pub fn to_cbor(&self) -> Cbor {
        Cbor::map(
            self.pcrs
                .iter()
                .enumerate()
                .map(|(i, p)| (Cbor::UInt(i as u64), Cbor::bytes(p.to_vec())))
                .collect::<Vec<_>>(),
        )
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let items = match v {
            Cbor::Map(items) => items,
            _ => return None,
        };
        let mut bank = PcrBank::new();
        for (k, val) in items {
            let idx = k.as_u64()? as usize;
            if idx >= PCR_COUNT {
                return None;
            }
            let b = val.as_bytes()?;
            if b.len() != 32 {
                return None;
            }
            bank.pcrs[idx].copy_from_slice(b);
        }
        Some(bank)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_semantics() {
        let mut b = PcrBank::new();
        assert_eq!(b.get(PCR_KERNEL), [0u8; 32]);
        b.extend(PCR_KERNEL, b"image-hash-1");
        let after1 = b.get(PCR_KERNEL);
        assert_ne!(after1, [0u8; 32]);
        // детерминизм: тот же порядок extend → тот же PCR
        let mut b2 = PcrBank::new();
        b2.extend(PCR_KERNEL, b"image-hash-1");
        assert_eq!(b2.get(PCR_KERNEL), after1);
        // порядок измерений важен
        let mut b3 = PcrBank::new();
        b3.extend(PCR_KERNEL, b"b");
        b3.extend(PCR_KERNEL, b"a");
        let mut b4 = PcrBank::new();
        b4.extend(PCR_KERNEL, b"a");
        b4.extend(PCR_KERNEL, b"b");
        assert_ne!(b3.get(PCR_KERNEL), b4.get(PCR_KERNEL));
        // log
        assert_eq!(b.log().len(), 1);
        assert_eq!(b.log()[0].0, PCR_KERNEL);
    }

    #[test]
    fn cbor_roundtrip() {
        let mut b = PcrBank::new();
        b.extend(PCR_SBL, b"sbl");
        b.extend(PCR_HSM_STATUS, b"hsm-ok");
        let v = b.to_cbor();
        let enc = v.to_vec();
        let dec = Cbor::from_slice(&enc).unwrap();
        let b2 = PcrBank::from_cbor(&dec).unwrap();
        assert_eq!(b2.get(PCR_SBL), b.get(PCR_SBL));
        assert_eq!(b2.get(PCR_HSM_STATUS), b.get(PCR_HSM_STATUS));
    }
}
