//! Trust bundle — PKI-материалы кластера (§23.4 PKI design):
//! root PK, Platform CA cert, подписанты прошивок/обновлений, сертификаты
//! устройств и операторов (с ролями), CRL. Формат — canonical CBOR (DM-1).

use crate::cert::{SignerCert, USAGE_CA};
use crate::anchor::TrustAnchor;
use sakura_common::cbor::Cbor;
use sakura_hybrid::HybridPublicKey;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct RosterEntry {
    pub idx: u32,
    pub node_id: [u8; 16],
    pub host: String,
    pub port: u16,
    pub http_port: u16,
}

#[derive(Clone, Debug)]
pub struct TrustBundle {
    pub root_pk: HybridPublicKey,
    pub platform_cert: SignerCert,
    pub firmware_cert: SignerCert,
    pub update_cert: SignerCert,
    pub device_certs: BTreeMap<[u8; 16], SignerCert>,
    /// оператор → (сертификат, роль).
    pub operator_certs: BTreeMap<[u8; 16], (SignerCert, String)>,
    pub crl: Vec<[u8; 16]>,
    pub roster: Vec<RosterEntry>,
}

impl TrustBundle {
    pub fn anchor(&self) -> TrustAnchor {
        TrustAnchor::new(self.root_pk.clone(), self.crl.clone())
    }

    /// Цепочка сертификата подписанта прошивок: [firmware_cert, platform_cert].
    pub fn firmware_chain(&self) -> Vec<SignerCert> {
        vec![self.firmware_cert.clone(), self.platform_cert.clone()]
    }

    pub fn update_chain(&self) -> Vec<SignerCert> {
        vec![self.update_cert.clone(), self.platform_cert.clone()]
    }

    /// Цепочка сертификата устройства: [device_cert, platform_cert].
    pub fn device_chain(&self, node_id: &[u8; 16]) -> Option<Vec<SignerCert>> {
        Some(vec![
            self.device_certs.get(node_id)?.clone(),
            self.platform_cert.clone(),
        ])
    }

    pub fn operator_role(&self, principal: &[u8; 16]) -> Option<&str> {
        self.operator_certs.get(principal).map(|(_, r)| r.as_str())
    }

    pub fn to_cbor(&self) -> Cbor {
        let dev: Vec<(Cbor, Cbor)> = self
            .device_certs
            .iter()
            .map(|(id, c)| (Cbor::bytes(id.to_vec()), Cbor::bytes(c.encode())))
            .collect();
        let ops: Vec<(Cbor, Cbor)> = self
            .operator_certs
            .iter()
            .map(|(id, (c, role))| {
                (
                    Cbor::bytes(id.to_vec()),
                    Cbor::array(vec![Cbor::bytes(c.encode()), Cbor::text(role.clone())]),
                )
            })
            .collect();
        let roster: Vec<Cbor> = self
            .roster
            .iter()
            .map(|r| {
                Cbor::map(vec![
                    (Cbor::text("idx"), Cbor::UInt(r.idx as u64)),
                    (Cbor::text("node_id"), Cbor::bytes(r.node_id.to_vec())),
                    (Cbor::text("host"), Cbor::text(r.host.clone())),
                    (Cbor::text("port"), Cbor::UInt(r.port as u64)),
                    (Cbor::text("http_port"), Cbor::UInt(r.http_port as u64)),
                ])
            })
            .collect();
        Cbor::map(vec![
            (Cbor::text("version"), Cbor::UInt(1)),
            (Cbor::text("root_pk"), Cbor::bytes(self.root_pk.to_bytes())),
            (Cbor::text("platform_cert"), Cbor::bytes(self.platform_cert.encode())),
            (Cbor::text("firmware_cert"), Cbor::bytes(self.firmware_cert.encode())),
            (Cbor::text("update_cert"), Cbor::bytes(self.update_cert.encode())),
            (Cbor::text("device_certs"), Cbor::map(dev)),
            (Cbor::text("operator_certs"), Cbor::map(ops)),
            (
                Cbor::text("crl"),
                Cbor::array(self.crl.iter().map(|c| Cbor::bytes(c.to_vec())).collect()),
            ),
            (Cbor::text("roster"), Cbor::array(roster)),
        ])
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let pk_b = v.get("root_pk")?.as_bytes()?;
        let root_pk = HybridPublicKey::from_bytes(pk_b)?;
        let cert = |k: &str| -> Option<SignerCert> {
            SignerCert::decode(v.get(k)?.as_bytes()?)
        };
        let platform_cert = cert("platform_cert")?;
        // platform cert обязан быть CA (§23.4)
        if platform_cert.key_usage != USAGE_CA {
            return None;
        }
        let mut device_certs = BTreeMap::new();
        if let Cbor::Map(items) = v.get("device_certs")? {
            for (k, c) in items {
                let b = k.as_bytes()?;
                if b.len() != 16 {
                    return None;
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(b);
                device_certs.insert(id, SignerCert::decode(c.as_bytes()?)?);
            }
        }
        let mut operator_certs = BTreeMap::new();
        if let Cbor::Map(items) = v.get("operator_certs")? {
            for (k, c) in items {
                let b = k.as_bytes()?;
                if b.len() != 16 {
                    return None;
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(b);
                let arr = c.as_array()?;
                operator_certs.insert(
                    id,
                    (SignerCert::decode(arr[0].as_bytes()?)?, arr[1].as_text()?.to_owned()),
                );
            }
        }
        let mut crl = Vec::new();
        for c in v.get("crl")?.as_array()? {
            let b = c.as_bytes()?;
            if b.len() != 16 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            crl.push(a);
        }
        let mut roster = Vec::new();
        for r in v.get("roster")?.as_array()? {
            let b = r.get("node_id")?.as_bytes()?;
            if b.len() != 16 {
                return None;
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(b);
            roster.push(RosterEntry {
                idx: r.get("idx")?.as_u64()? as u32,
                node_id: id,
                host: r.get("host")?.as_text()?.to_owned(),
                port: r.get("port")?.as_u64()? as u16,
                http_port: r.get("http_port")?.as_u64()? as u16,
            });
        }
        Some(TrustBundle {
            root_pk,
            platform_cert,
            firmware_cert: cert("firmware_cert")?,
            update_cert: cert("update_cert")?,
            device_certs,
            operator_certs,
            crl,
            roster,
        })
    }

    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_cbor().to_vec())
    }

    pub fn load(path: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read(path).ok()?;
        let v = Cbor::from_slice(&raw).ok()?;
        Self::from_cbor(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{key_id_of_pub, USAGE_FIRMWARE_SIGN};
    use sakura_hybrid::{hybrid_sign, HybridKeyPair};

    #[test]
    fn bundle_roundtrip() {
        let root = HybridKeyPair::generate().unwrap();
        let platform = HybridKeyPair::generate().unwrap();
        let fw = HybridKeyPair::generate().unwrap();
        let dev = HybridKeyPair::generate().unwrap();
        let op = HybridKeyPair::generate().unwrap();

        let mk = |kp: &HybridKeyPair, usage: u8, subj: [u8; 16]| -> SignerCert {
            let mut c = SignerCert {
                subject_id: subj,
                signer_id: key_id_of_pub(&root.public),
                public: kp.public.clone(),
                key_usage: usage,
                hw_rev_min: 1,
                not_before: 0,
                not_after: u64::MAX,
                signature: Vec::new(),
            };
            c.signature = hybrid_sign(&root, &c.tbs()).unwrap();
            c
        };
        let platform_cert = mk(&platform, USAGE_CA, [1u8; 16]);
        // перевыпуск: platform_cert подписывает fw/dev/op от platform CA
        let mk2 = |kp: &HybridKeyPair, usage: u8, subj: [u8; 16]| -> SignerCert {
            let mut c = SignerCert {
                subject_id: subj,
                signer_id: key_id_of_pub(&platform.public),
                public: kp.public.clone(),
                key_usage: usage,
                hw_rev_min: 1,
                not_before: 0,
                not_after: u64::MAX,
                signature: Vec::new(),
            };
            c.signature = hybrid_sign(&platform, &c.tbs()).unwrap();
            c
        };
        let fw_cert = mk2(&fw, USAGE_FIRMWARE_SIGN, [2u8; 16]);
        let dev_cert = mk2(&dev, crate::cert::USAGE_DEVICE_IDENTITY, [3u8; 16]);
        let op_cert = mk2(&op, crate::cert::USAGE_OPERATOR, [4u8; 16]);

        let bundle = TrustBundle {
            root_pk: root.public.clone(),
            platform_cert: platform_cert.clone(),
            firmware_cert: fw_cert.clone(),
            update_cert: fw_cert.clone(),
            device_certs: BTreeMap::from([([3u8; 16], dev_cert)]),
            operator_certs: BTreeMap::from([([4u8; 16], (op_cert, "OPERATOR".to_owned()))]),
            crl: vec![[9u8; 16]],
            roster: vec![RosterEntry {
                idx: 0,
                node_id: [3u8; 16],
                host: "127.0.0.1".into(),
                port: 9100,
                http_port: 9200,
            }],
        };
        let enc = bundle.to_cbor().to_vec();
        let dec = TrustBundle::from_cbor(&Cbor::from_slice(&enc).unwrap()).unwrap();
        assert_eq!(dec.roster.len(), 1);
        assert_eq!(dec.crl, vec![[9u8; 16]]);
        assert_eq!(dec.operator_role(&[4u8; 16]), Some("OPERATOR"));

        // цепочка firmware проверяется anchor'ом
        let anchor = dec.anchor();
        let chain = vec![dec.firmware_cert.clone(), dec.platform_cert.clone()];
        anchor
            .verify_chain(&chain, &dec.firmware_cert.subject_id, Some(1000))
            .unwrap();
        // цепочка устройства — через verify_chain_for_usage
        let dchain = dec.device_chain(&[3u8; 16]).unwrap();
        anchor.verify_chain_for_usage(&dchain, &[3u8; 16], Some(1000)).unwrap();
        // отозванный — в CRL
        let mut b2 = dec.clone();
        b2.crl.push(fw_cert.subject_key_id());
        let a2 = b2.anchor();
        assert!(matches!(
            a2.verify_chain(&chain, &fw_cert.subject_id, Some(1000)),
            Err(crate::image::BootError::Revoked)
        ));
    }
}
