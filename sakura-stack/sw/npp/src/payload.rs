//! Прикладные сообщения NPP (API-1 §13.19, DM-1 §13.18): канонические
//! CBOR-запросы/ответы control-плоскости и внутренних плоскостей.
//!
//! Расширение типов сообщений (аддендум ICD-1, зарегистрирован в
//! docs/TRACEABILITY.md): базовая таблица §13.3 дополнена внутренними
//! типами платформы:
//! - 0x70 CONSENSUS_MSG — сообщения SakuraBFT (Proposal/Vote/ViewChange…);
//! - 0x71 CRDT_SYNC — операции/снапшоты CRDT-репликации;
//! - 0x72 CONTROL_API — RPC клиент(CLI)↔узел (SubmitCommand и пр.);
//! - 0x73 TIME_SYNC — PTP-подобный обмен (t1/t2/t3/t4, §12).
//!
//! Каждый ответ API содержит: result (OK / код §13.8), request_seq (эхо),
//! audit_ref (ссылка на запись журнала) — §13.19.3.

use sakura_common::cbor::Cbor;
use sakura_common::uuid7::Uuid7;

// --- расширения таблицы типов §13.3 (аддендум ICD-1) ---
pub const TYPE_CONSENSUS_MSG: u8 = 0x70;
pub const TYPE_CRDT_SYNC: u8 = 0x71;
pub const TYPE_CONTROL_API: u8 = 0x72;
pub const TYPE_TIME_SYNC: u8 = 0x73;

pub const API_VERSION: &str = "control.v1";

// ---------------- Control API (API-1 §13.19.2) ----------------

#[derive(Clone, Debug)]
pub enum ApiRequest {
    SubmitCommand {
        plan_id: [u8; 16],
        command_id: [u8; 16],
        seq: u64,
        cmd_type: String,
        payload: Vec<u8>,
        target: String,
        cmd_sig: Vec<u8>,
        /// Публичный ключ оператора (сертификат проверяется узлом по цепочке).
        operator_pk: Vec<u8>,
        operator_cert: Vec<u8>,
        operator_role: String,
        authz_token: Vec<u8>,
        idempotency_key: Vec<u8>,
        request_seq: u64,
        /// Вторая подпись (two-person rule) — опционально.
        second_sig: Option<(Vec<u8>, Vec<u8>)>, // (pk, sig)
    },
    GetStatus {
        node_id: Option<[u8; 16]>,
        request_seq: u64,
    },
    RequestAttestation {
        nonce: Vec<u8>,
        request_seq: u64,
    },
    EmergencyStop {
        reason_code: u32,
        op_sig: Vec<u8>,
        op_pk: Vec<u8>,
        op_cert: Vec<u8>,
        second_op_sig: Vec<u8>,
        second_op_pk: Vec<u8>,
        request_seq: u64,
        idempotency_key: Vec<u8>,
    },
    UpdateCommit {
        package: Vec<u8>,
        request_seq: u64,
        idempotency_key: Vec<u8>,
    },
    AuditExport {
        request_id: Vec<u8>,
        from_seq: u64,
        max_records: u64,
        request_seq: u64,
        authz_token: Vec<u8>,
    },
    KvGet {
        key: String,
        request_seq: u64,
    },
    KvList {
        request_seq: u64,
    },
}

#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub result: String,
    pub request_seq: u64,
    pub audit_ref: Uuid7,
    pub data: Option<Cbor>,
}

impl ApiResponse {
    pub fn ok(request_seq: u64, audit_ref: Uuid7, data: Option<Cbor>) -> Self {
        ApiResponse { result: "OK".into(), request_seq, audit_ref, data }
    }
    pub fn err(request_seq: u64, audit_ref: Uuid7, code: sakura_common::ErrorCode) -> Self {
        ApiResponse { result: code.as_str().into(), request_seq, audit_ref, data: None }
    }
    pub fn to_cbor(&self) -> Cbor {
        let mut items = vec![
            (Cbor::text("api"), Cbor::text(API_VERSION)),
            (Cbor::text("result"), Cbor::text(self.result.clone())),
            (Cbor::text("request_seq"), Cbor::UInt(self.request_seq)),
            (Cbor::text("audit_ref"), Cbor::bytes(self.audit_ref.as_bytes().to_vec())),
        ];
        if let Some(d) = &self.data {
            items.push((Cbor::text("data"), d.clone()));
        }
        Cbor::map(items)
    }
    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let b = v.get("audit_ref")?.as_bytes()?;
        let mut a = [0u8; 16];
        if b.len() != 16 {
            return None;
        }
        a.copy_from_slice(b);
        Some(ApiResponse {
            result: v.get("result")?.as_text()?.to_owned(),
            request_seq: v.get("request_seq")?.as_u64()?,
            audit_ref: Uuid7(a),
            data: v.get("data").cloned(),
        })
    }
}

impl ApiRequest {
    pub fn op_name(&self) -> &'static str {
        match self {
            ApiRequest::SubmitCommand { .. } => "SubmitCommand",
            ApiRequest::GetStatus { .. } => "GetStatus",
            ApiRequest::RequestAttestation { .. } => "RequestAttestation",
            ApiRequest::EmergencyStop { .. } => "EmergencyStop",
            ApiRequest::UpdateCommit { .. } => "UpdateCommit",
            ApiRequest::AuditExport { .. } => "AuditExport",
            ApiRequest::KvGet { .. } => "KvGet",
            ApiRequest::KvList { .. } => "KvList",
        }
    }

    pub fn request_seq(&self) -> u64 {
        match self {
            ApiRequest::SubmitCommand { request_seq, .. } => *request_seq,
            ApiRequest::GetStatus { request_seq, .. } => *request_seq,
            ApiRequest::RequestAttestation { request_seq, .. } => *request_seq,
            ApiRequest::EmergencyStop { request_seq, .. } => *request_seq,
            ApiRequest::UpdateCommit { request_seq, .. } => *request_seq,
            ApiRequest::AuditExport { request_seq, .. } => *request_seq,
            ApiRequest::KvGet { request_seq, .. } => *request_seq,
            ApiRequest::KvList { request_seq, .. } => *request_seq,
        }
    }

    pub fn idempotency_key(&self) -> Option<&[u8]> {
        match self {
            ApiRequest::SubmitCommand { idempotency_key, .. } => Some(idempotency_key),
            ApiRequest::EmergencyStop { idempotency_key, .. } => Some(idempotency_key),
            ApiRequest::UpdateCommit { idempotency_key, .. } => Some(idempotency_key),
            ApiRequest::AuditExport { request_id, .. } => Some(request_id),
            _ => None,
        }
    }

    pub fn to_cbor(&self) -> Cbor {
        let mut items: Vec<(Cbor, Cbor)> = vec![
            (Cbor::text("api"), Cbor::text(API_VERSION)),
            (Cbor::text("op"), Cbor::text(self.op_name())),
        ];
        match self {
            ApiRequest::SubmitCommand {
                plan_id, command_id, seq, cmd_type, payload, target, cmd_sig,
                operator_pk, operator_cert, operator_role, authz_token,
                idempotency_key, request_seq, second_sig,
            } => {
                items.extend([
                    (Cbor::text("plan_id"), Cbor::bytes(plan_id.to_vec())),
                    (Cbor::text("command_id"), Cbor::bytes(command_id.to_vec())),
                    (Cbor::text("seq"), Cbor::UInt(*seq)),
                    (Cbor::text("cmd_type"), Cbor::text(cmd_type.clone())),
                    (Cbor::text("payload"), Cbor::bytes(payload.clone())),
                    (Cbor::text("target"), Cbor::text(target.clone())),
                    (Cbor::text("cmd_sig"), Cbor::bytes(cmd_sig.clone())),
                    (Cbor::text("operator_pk"), Cbor::bytes(operator_pk.clone())),
                    (Cbor::text("operator_cert"), Cbor::bytes(operator_cert.clone())),
                    (Cbor::text("operator_role"), Cbor::text(operator_role.clone())),
                    (Cbor::text("authz_token"), Cbor::bytes(authz_token.clone())),
                    (Cbor::text("idempotency_key"), Cbor::bytes(idempotency_key.clone())),
                    (Cbor::text("request_seq"), Cbor::UInt(*request_seq)),
                    (
                        Cbor::text("second_sig"),
                        match second_sig {
                            Some((pk, sig)) => Cbor::array(vec![Cbor::bytes(pk.clone()), Cbor::bytes(sig.clone())]),
                            None => Cbor::Null,
                        },
                    ),
                ]);
            }
            ApiRequest::GetStatus { node_id, request_seq } => {
                items.push((Cbor::text("request_seq"), Cbor::UInt(*request_seq)));
                items.push((
                    Cbor::text("node_id"),
                    node_id.map(|n| Cbor::bytes(n.to_vec())).unwrap_or(Cbor::Null),
                ));
            }
            ApiRequest::RequestAttestation { nonce, request_seq } => {
                items.push((Cbor::text("nonce"), Cbor::bytes(nonce.clone())));
                items.push((Cbor::text("request_seq"), Cbor::UInt(*request_seq)));
            }
            ApiRequest::EmergencyStop {
                reason_code, op_sig, op_pk, op_cert, second_op_sig, second_op_pk,
                request_seq, idempotency_key,
            } => {
                items.extend([
                    (Cbor::text("reason_code"), Cbor::UInt(*reason_code as u64)),
                    (Cbor::text("op_sig"), Cbor::bytes(op_sig.clone())),
                    (Cbor::text("op_pk"), Cbor::bytes(op_pk.clone())),
                    (Cbor::text("op_cert"), Cbor::bytes(op_cert.clone())),
                    (Cbor::text("second_op_sig"), Cbor::bytes(second_op_sig.clone())),
                    (Cbor::text("second_op_pk"), Cbor::bytes(second_op_pk.clone())),
                    (Cbor::text("request_seq"), Cbor::UInt(*request_seq)),
                    (Cbor::text("idempotency_key"), Cbor::bytes(idempotency_key.clone())),
                ]);
            }
            ApiRequest::UpdateCommit { package, request_seq, idempotency_key } => {
                items.extend([
                    (Cbor::text("package"), Cbor::bytes(package.clone())),
                    (Cbor::text("request_seq"), Cbor::UInt(*request_seq)),
                    (Cbor::text("idempotency_key"), Cbor::bytes(idempotency_key.clone())),
                ]);
            }
            ApiRequest::AuditExport { request_id, from_seq, max_records, request_seq, authz_token } => {
                items.extend([
                    (Cbor::text("request_id"), Cbor::bytes(request_id.clone())),
                    (Cbor::text("from_seq"), Cbor::UInt(*from_seq)),
                    (Cbor::text("max_records"), Cbor::UInt(*max_records)),
                    (Cbor::text("request_seq"), Cbor::UInt(*request_seq)),
                    (Cbor::text("authz_token"), Cbor::bytes(authz_token.clone())),
                ]);
            }
            ApiRequest::KvGet { key, request_seq } => {
                items.push((Cbor::text("key"), Cbor::text(key.clone())));
                items.push((Cbor::text("request_seq"), Cbor::UInt(*request_seq)));
            }
            ApiRequest::KvList { request_seq } => {
                items.push((Cbor::text("request_seq"), Cbor::UInt(*request_seq)));
            }
        }
        Cbor::map(items)
    }

    pub fn from_cbor(v: &Cbor) -> Option<Self> {
        let b16opt = |k: &str| -> Option<Option<[u8; 16]>> {
            match v.get(k)? {
                Cbor::Null => Some(None),
                Cbor::Bytes(b) if b.len() == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    Some(Some(a))
                }
                _ => None,
            }
        };
        let b16 = |k: &str| -> Option<[u8; 16]> { b16opt(k)? };
        let bytes = |k: &str| -> Option<Vec<u8>> { v.get(k)?.as_bytes().map(|b| b.to_vec()) };
        let opt_bytes = |k: &str| -> Option<Vec<u8>> {
            match v.get(k)? {
                Cbor::Null => Some(Vec::new()),
                Cbor::Bytes(b) => Some(b.clone()),
                _ => None,
            }
        };
        match v.get("op")?.as_text()? {
            "SubmitCommand" => {
                let second_sig = match v.get("second_sig")? {
                    Cbor::Null => None,
                    Cbor::Array(a) if a.len() == 2 => {
                        Some((a[0].as_bytes()?.to_vec(), a[1].as_bytes()?.to_vec()))
                    }
                    _ => return None,
                };
                Some(ApiRequest::SubmitCommand {
                    plan_id: b16("plan_id")?,
                    command_id: b16("command_id")?,
                    seq: v.get("seq")?.as_u64()?,
                    cmd_type: v.get("cmd_type")?.as_text()?.to_owned(),
                    payload: bytes("payload")?,
                    target: v.get("target")?.as_text()?.to_owned(),
                    cmd_sig: bytes("cmd_sig")?,
                    operator_pk: bytes("operator_pk")?,
                    operator_cert: bytes("operator_cert")?,
                    operator_role: v.get("operator_role")?.as_text()?.to_owned(),
                    authz_token: opt_bytes("authz_token")?,
                    idempotency_key: bytes("idempotency_key")?,
                    request_seq: v.get("request_seq")?.as_u64()?,
                    second_sig,
                })
            }
            "GetStatus" => Some(ApiRequest::GetStatus {
                node_id: b16opt("node_id")?,
                request_seq: v.get("request_seq")?.as_u64()?,
            }),
            "RequestAttestation" => Some(ApiRequest::RequestAttestation {
                nonce: bytes("nonce")?,
                request_seq: v.get("request_seq")?.as_u64()?,
            }),
            "EmergencyStop" => Some(ApiRequest::EmergencyStop {
                reason_code: v.get("reason_code")?.as_u64()? as u32,
                op_sig: bytes("op_sig")?,
                op_pk: bytes("op_pk")?,
                op_cert: bytes("op_cert")?,
                second_op_sig: bytes("second_op_sig")?,
                second_op_pk: bytes("second_op_pk")?,
                request_seq: v.get("request_seq")?.as_u64()?,
                idempotency_key: bytes("idempotency_key")?,
            }),
            "UpdateCommit" => Some(ApiRequest::UpdateCommit {
                package: bytes("package")?,
                request_seq: v.get("request_seq")?.as_u64()?,
                idempotency_key: bytes("idempotency_key")?,
            }),
            "AuditExport" => Some(ApiRequest::AuditExport {
                request_id: bytes("request_id")?,
                from_seq: v.get("from_seq")?.as_u64()?,
                max_records: v.get("max_records")?.as_u64()?,
                request_seq: v.get("request_seq")?.as_u64()?,
                authz_token: opt_bytes("authz_token")?,
            }),
            "KvGet" => Some(ApiRequest::KvGet {
                key: v.get("key")?.as_text()?.to_owned(),
                request_seq: v.get("request_seq")?.as_u64()?,
            }),
            "KvList" => Some(ApiRequest::KvList {
                request_seq: v.get("request_seq")?.as_u64()?,
            }),
            _ => None,
        }
    }
}

// ---------------- Consensus plane (0x70) ----------------

/// Сообщения консенсуса в CBOR (транспорт — NPP-кадры типа 0x70).
pub mod consensus_wire {
    use sakura_common::cbor::Cbor;

    pub fn block_to_cbor(
        height: u64,
        view: u64,
        parent_hash: &[u8; 32],
        payload: &[u8],
        proposer: u32,
    ) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("height"), Cbor::UInt(height)),
            (Cbor::text("view"), Cbor::UInt(view)),
            (Cbor::text("parent_hash"), Cbor::bytes(parent_hash.to_vec())),
            (Cbor::text("payload"), Cbor::bytes(payload.to_vec())),
            (Cbor::text("proposer"), Cbor::UInt(proposer as u64)),
        ])
    }

    pub fn block_from_cbor(v: &Cbor) -> Option<(u64, u64, [u8; 32], Vec<u8>, u32)> {
        let ph = v.get("parent_hash")?.as_bytes()?;
        if ph.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(ph);
        Some((
            v.get("height")?.as_u64()?,
            v.get("view")?.as_u64()?,
            h,
            v.get("payload")?.as_bytes()?.to_vec(),
            v.get("proposer")?.as_u64()? as u32,
        ))
    }

    pub fn vote_to_cbor(
        block_hash: &[u8; 32],
        voter: u32,
        view: u64,
        phase: u8,
        signature: &[u8],
    ) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("block_hash"), Cbor::bytes(block_hash.to_vec())),
            (Cbor::text("voter"), Cbor::UInt(voter as u64)),
            (Cbor::text("view"), Cbor::UInt(view)),
            (Cbor::text("phase"), Cbor::UInt(phase as u64)),
            (Cbor::text("signature"), Cbor::bytes(signature.to_vec())),
        ])
    }

    pub fn vote_from_cbor(v: &Cbor) -> Option<([u8; 32], u32, u64, u8, Vec<u8>)> {
        let bh = v.get("block_hash")?.as_bytes()?;
        if bh.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(bh);
        Some((
            h,
            v.get("voter")?.as_u64()? as u32,
            v.get("view")?.as_u64()?,
            v.get("phase")?.as_u64()? as u8,
            v.get("signature")?.as_bytes()?.to_vec(),
        ))
    }

    pub fn viewchange_to_cbor(kind: &str, view: u64, node: u32, sig: &[u8]) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text(kind)),
            (Cbor::text("view"), Cbor::UInt(view)),
            (Cbor::text("node"), Cbor::UInt(node as u64)),
            (Cbor::text("sig"), Cbor::bytes(sig.to_vec())),
        ])
    }

    pub fn viewchange_from_cbor(v: &Cbor) -> Option<(String, u64, u32, Vec<u8>)> {
        Some((
            v.get("kind")?.as_text()?.to_owned(),
            v.get("view")?.as_u64()?,
            v.get("node")?.as_u64()? as u32,
            v.get("sig")?.as_bytes()?.to_vec(),
        ))
    }

    pub fn sync_to_cbor(
        kind: &str,
        node: u32,
        height: u64,
        finalized: &[(u64, [u8; 32])],
        blocks: &[Cbor],
    ) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text(kind)),
            (Cbor::text("node"), Cbor::UInt(node as u64)),
            (Cbor::text("height"), Cbor::UInt(height)),
            (
                Cbor::text("finalized"),
                Cbor::array(
                    finalized
                        .iter()
                        .map(|(h, x)| {
                            Cbor::array(vec![Cbor::UInt(*h), Cbor::bytes(x.to_vec())])
                        })
                        .collect(),
                ),
            ),
            (Cbor::text("blocks"), Cbor::array(blocks.to_vec())),
        ])
    }

    pub fn sync_from_cbor(
        v: &Cbor,
    ) -> Option<(String, u32, u64, Vec<(u64, [u8; 32])>, Vec<Cbor>)> {
        let mut fin = Vec::new();
        for it in v.get("finalized")?.as_array()? {
            let arr = it.as_array()?;
            let b = arr[1].as_bytes()?;
            if b.len() != 32 {
                return None;
            }
            let mut x = [0u8; 32];
            x.copy_from_slice(b);
            fin.push((arr[0].as_u64()?, x));
        }
        let blocks = v.get("blocks").and_then(|x| x.as_array()).map(|a| a.to_vec()).unwrap_or_default();
        Some((
            v.get("kind")?.as_text()?.to_owned(),
            v.get("node")?.as_u64()? as u32,
            v.get("height")?.as_u64()?,
            fin,
            blocks,
        ))
    }
}

// ---------------- CRDT plane (0x71) ----------------

pub mod crdt_wire {
    use sakura_common::cbor::Cbor;

    pub fn op_message(key: &str, op: &Cbor) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text("op")),
            (Cbor::text("key"), Cbor::text(key.to_owned())),
            (Cbor::text("op"), op.clone()),
        ])
    }

    pub fn snapshot_message(state: &Cbor, node: u32, height: u64) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text("snapshot")),
            (Cbor::text("state"), state.clone()),
            (Cbor::text("node"), Cbor::UInt(node as u64)),
            (Cbor::text("height"), Cbor::UInt(height)),
        ])
    }
}

// ---------------- Time sync plane (0x73, §12 PTP-подобно) ----------------

pub mod time_wire {
    use sakura_common::cbor::Cbor;

    /// SYNC: t1 (отправитель); SYNC_ACK: t_ns = t2/t3, t1_ns — эхо.
    pub fn msg(kind: &str, t_ns: u64, seq: u64) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text(kind.to_owned())),
            (Cbor::text("t_ns"), Cbor::UInt(t_ns)),
            (Cbor::text("seq"), Cbor::UInt(seq)),
        ])
    }
    pub fn msg_ack(t2_ns: u64, seq: u64, t1_ns: u64) -> Cbor {
        Cbor::map(vec![
            (Cbor::text("kind"), Cbor::text("sync_ack")),
            (Cbor::text("t_ns"), Cbor::UInt(t2_ns)),
            (Cbor::text("seq"), Cbor::UInt(seq)),
            (Cbor::text("t1_ns"), Cbor::UInt(t1_ns)),
        ])
    }
    pub fn parse(v: &Cbor) -> Option<(String, u64, u64)> {
        Some((
            v.get("kind")?.as_text()?.to_owned(),
            v.get("t_ns")?.as_u64()?,
            v.get("seq")?.as_u64()?,
        ))
    }
    pub fn parse_t1(v: &Cbor) -> Option<u64> {
        v.get("t1_ns")?.as_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_request_roundtrip() {
        let req = ApiRequest::SubmitCommand {
            plan_id: [1u8; 16],
            command_id: [2u8; 16],
            seq: 7,
            cmd_type: "KV_PUT".into(),
            payload: b"value".to_vec(),
            target: "node-1".into(),
            cmd_sig: vec![3u8; 3373],
            operator_pk: vec![4u8; 3584],
            operator_cert: vec![5u8; 100],
            operator_role: "OPERATOR".into(),
            authz_token: vec![6u8; 32],
            idempotency_key: vec![7u8; 16],
            request_seq: 7,
            second_sig: None,
        };
        let enc = req.to_cbor().to_vec();
        let dec = ApiRequest::from_cbor(&Cbor::from_slice(&enc).unwrap()).unwrap();
        assert_eq!(dec.op_name(), "SubmitCommand");
        assert_eq!(dec.request_seq(), 7);
        if let ApiRequest::SubmitCommand { cmd_type, seq, second_sig, .. } = dec {
            assert_eq!(cmd_type, "KV_PUT");
            assert_eq!(seq, 7);
            assert!(second_sig.is_none());
        } else {
            panic!();
        }
    }

    #[test]
    fn api_response_contract() {
        let r = ApiResponse::ok(7, Uuid7([8u8; 16]), Some(Cbor::text("value")));
        let enc = r.to_cbor().to_vec();
        let dec = ApiResponse::from_cbor(&Cbor::from_slice(&enc).unwrap()).unwrap();
        assert_eq!(dec.result, "OK");
        assert_eq!(dec.request_seq, 7);
        assert_eq!(dec.data.unwrap().as_text(), Some("value"));
        // §13.19.3: отказ содержит код из 13.8
        let e = ApiResponse::err(7, Uuid7([9u8; 16]), sakura_common::ErrorCode::PolicyViolation);
        assert_eq!(e.result, "POLICY_VIOLATION");
    }

    #[test]
    fn consensus_wire_roundtrip() {
        let b = consensus_wire::block_to_cbor(3, 1, &[0xAB; 32], b"payload", 2);
        let (h, v, ph, pl, pr) =
            consensus_wire::block_from_cbor(&Cbor::from_slice(&b.to_vec()).unwrap()).unwrap();
        assert_eq!((h, v, pr), (3, 1, 2));
        assert_eq!(ph, [0xAB; 32]);
        assert_eq!(pl, b"payload");

        let vote = consensus_wire::vote_to_cbor(&[1u8; 32], 4, 2, 1, &[9u8; 64]);
        let (bh, voter, view, phase, sig) =
            consensus_wire::vote_from_cbor(&Cbor::from_slice(&vote.to_vec()).unwrap()).unwrap();
        assert_eq!(bh, [1u8; 32]);
        assert_eq!((voter, view, phase), (4, 2, 1));
        assert_eq!(sig, vec![9u8; 64]);
    }
}
