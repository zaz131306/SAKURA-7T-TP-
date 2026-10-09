//! Транспорт NPP поверх TCP + установление сессии (§13.3, §13.17):
//! HELLO → AUTH_CHALLENGE → AUTH_RESPONSE → SESSION_ESTABLISH →
//! SESSION_CONFIRM → зашифрованные кадры (Кузнечик-MGM, BC-21).
//!
//! Channel binding = хэш транскрипта рукопожатия (§13.17);
//! anti-replay = seq-окно на соединение + nonce в рукопожатии;
//! IV MGM = направление||seq (no IV reuse, BC-21).

use sakura_boot::anchor::TrustAnchor;
use sakura_boot::cert::{SignerCert, USAGE_DEVICE_IDENTITY, USAGE_OPERATOR};
use sakura_common::cbor::Cbor;
use sakura_gost::hash::streebog256;
use sakura_hybrid::hybrid_kem_combine;
use sakura_npp::frame::{Frame, FrameError, NppCodec};
use sakura_npp::msg::MsgType;
use sakura_npp::replay::ReplayWindow;
use sakura_npp::NppErrCode;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

pub const PROTOCOL_ID: &str = "NPP-v2.3";
pub const READ_TIMEOUT: Duration = Duration::from_millis(2);
pub use sakura_npp::frame::FRAG_UNIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    Io,
    Closed,
    Frame(FrameError),
    Handshake(NppErrCode),
    Crypto,
    Replay(NppErrCode),
}

/// Роль участника рукопожатия.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    Node,
    Operator,
}

// ---------------- рукопожатие: сообщения ----------------

/// HELLO (§13.3): сертификаты НЕ передаются — сервер берёт их из
/// trust bundle по id (provisioned roster; исключает TOFU).
pub fn hello_payload(
    kind: PrincipalKind,
    id: [u8; 16],
    nonce: [u8; 32],
    hw_rev: u16,
) -> Vec<u8> {
    Cbor::map(vec![
        (Cbor::text("v"), Cbor::UInt(1)),
        (Cbor::text("kind"), Cbor::text(match kind {
            PrincipalKind::Node => "node",
            PrincipalKind::Operator => "principal",
        })),
        (Cbor::text("id"), Cbor::bytes(id.to_vec())),
        (Cbor::text("nonce_c"), Cbor::bytes(nonce.to_vec())),
        (Cbor::text("hw_rev"), Cbor::UInt(hw_rev as u64)),
    ])
    .to_vec()
}

#[derive(Clone)]
pub struct HelloInfo {
    pub kind: PrincipalKind,
    pub id: [u8; 16],
    pub nonce_c: Vec<u8>,
    pub hw_rev: u16,
}

pub fn parse_hello(payload: &[u8]) -> Result<HelloInfo, NetError> {
    let v = Cbor::from_slice(payload).map_err(|_| NetError::Crypto)?;
    let kind = match v.get("kind").and_then(|k| k.as_text()) {
        Some("node") => PrincipalKind::Node,
        Some("principal") => PrincipalKind::Operator,
        _ => return Err(NetError::Handshake(NppErrCode::InvalidFrame)),
    };
    let id_b = v.get("id").and_then(|x| x.as_bytes()).ok_or(NetError::Crypto)?;
    if id_b.len() != 16 {
        return Err(NetError::Crypto);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(id_b);
    Ok(HelloInfo {
        kind,
        id,
        nonce_c: v.get("nonce_c").and_then(|x| x.as_bytes()).map(|b| b.to_vec()).unwrap_or_default(),
        hw_rev: v.get("hw_rev").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
    })
}

pub fn challenge_payload(nonce_s: [u8; 32]) -> Vec<u8> {
    Cbor::map(vec![(Cbor::text("nonce_s"), Cbor::bytes(nonce_s.to_vec()))])
        .to_vec()
}

pub fn auth_response_payload(sig: Vec<u8>) -> Vec<u8> {
    Cbor::map(vec![(Cbor::text("sig"), Cbor::bytes(sig))]).to_vec()
}

pub fn establish_payload(ukm: u64, eph_pub: [u8; 64], mlkem_ct: Vec<u8>) -> Vec<u8> {
    Cbor::map(vec![
        (Cbor::text("ukm"), Cbor::UInt(ukm)),
        (Cbor::text("eph_pub"), Cbor::bytes(eph_pub.to_vec())),
        (Cbor::text("mlkem_ct"), Cbor::bytes(mlkem_ct)),
    ])
    .to_vec()
}

pub struct EstablishInfo {
    pub ukm: u64,
    pub eph_pub: [u8; 64],
    pub mlkem_ct: Vec<u8>,
}

pub fn parse_establish(payload: &[u8]) -> Result<EstablishInfo, NetError> {
    let v = Cbor::from_slice(payload).map_err(|_| NetError::Crypto)?;
    let pk = v.get("eph_pub").and_then(|x| x.as_bytes()).ok_or(NetError::Crypto)?;
    if pk.len() != 64 {
        return Err(NetError::Crypto);
    }
    let mut eph = [0u8; 64];
    eph.copy_from_slice(pk);
    Ok(EstablishInfo {
        ukm: v.get("ukm").and_then(|x| x.as_u64()).ok_or(NetError::Crypto)?,
        eph_pub: eph,
        mlkem_ct: v.get("mlkem_ct").and_then(|x| x.as_bytes()).map(|b| b.to_vec()).ok_or(NetError::Crypto)?,
    })
}

pub fn confirm_payload(sig: Vec<u8>) -> Vec<u8> {
    Cbor::map(vec![(Cbor::text("sig"), Cbor::bytes(sig))]).to_vec()
}

// ---------------- соединение ----------------

pub struct Conn {
    pub stream: TcpStream,
    pub rx_buf: Vec<u8>,
    /// true — мы принимающая сторона (сервер рукопожатия).
    pub server_side: bool,
    pub established: bool,
    pub session_key: Option<[u8; 32]>,
    pub channel_binding: Option<[u8; 32]>,
    pub peer_id: Option<[u8; 16]>,
    pub peer_kind: Option<PrincipalKind>,
    pub peer_cert: Option<SignerCert>,
    pub seq_out: u64,
    pub replay: ReplayWindow,
    pub last_rx_ms: u64,
    /// накопитель рукопожатия
    pub hs: HandshakeState,
    /// реассемблер фрагментов (§13.3)
    pub reasm: ConnReassembler,
}

/// Обёртка FrameReassembler с интерфейсом по (src, mtype).
pub struct ConnReassembler {
    inner: sakura_npp::frame::FrameReassembler,
}

impl Default for ConnReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnReassembler {
    pub fn new() -> Self {
        ConnReassembler { inner: sakura_npp::frame::FrameReassembler::new() }
    }
    pub fn lock_frame(
        &mut self,
        src: u16,
        mtype: u8,
        frag: &[u8],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, sakura_npp::frame::ReassembleError> {
        self.inner.push(src, mtype, frag, now_ms)
    }
}

#[derive(Default)]
pub struct HandshakeState {
    pub h0: Vec<u8>,
    pub h1: Vec<u8>,
    pub h2: Vec<u8>,
    pub h3: Vec<u8>,
    pub step: u8,
}

impl Conn {
    pub fn new(stream: TcpStream, server_side: bool) -> Result<Self, NetError> {
        stream.set_read_timeout(Some(READ_TIMEOUT)).map_err(|_| NetError::Io)?;
        stream.set_nodelay(true).map_err(|_| NetError::Io)?;
        Ok(Conn {
            stream,
            rx_buf: Vec::new(),
            server_side,
            established: false,
            session_key: None,
            channel_binding: None,
            peer_id: None,
            peer_kind: None,
            peer_cert: None,
            seq_out: 0,
            replay: ReplayWindow::new(30),
            last_rx_ms: sakura_common::time::unix_ms(),
            hs: HandshakeState::default(),
            reasm: ConnReassembler::new(),
        })
    }

    fn direction(&self) -> u8 {
        if self.server_side {
            1
        } else {
            0
        }
    }

    fn mgm_iv(&self, seq: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[0] = 0; // MGM: старший бит nonce = 0
        iv[1] = self.direction();
        iv[2..10].copy_from_slice(&seq.to_be_bytes());
        // iv[10..16] = 0 — домен разделения направления/счётчика
        iv
    }

    fn aad_for(src: u16, dst: u16, seq: u32, mtype: u8, flags: u8) -> Vec<u8> {
        let mut aad = Vec::with_capacity(11);
        aad.extend_from_slice(&src.to_be_bytes());
        aad.extend_from_slice(&dst.to_be_bytes());
        aad.extend_from_slice(&seq.to_be_bytes());
        aad.push(mtype);
        aad.push(flags & (sakura_npp::frame::FLAG_ENCRYPTED | sakura_npp::frame::FLAG_FRAGMENT));
        aad
    }

    /// Отправка сообщения (после установления сессии — шифрование MGM);
    /// автоматически фрагментирует payload > FRAG_UNIT (FLAG_FRAGMENT).
    pub fn send_msg(
        &mut self,
        codec: &NppCodec,
        src: u16,
        dst: u16,
        mtype: u8,
        payload_plain: &[u8],
    ) -> Result<(), NetError> {
        let frags = sakura_npp::frame::split_fragments(payload_plain);
        let multi = frags.len() > 1;
        for frag in frags {
            self.send_one(codec, src, dst, mtype, &frag, multi)?;
        }
        Ok(())
    }

    fn send_one(
        &mut self,
        codec: &NppCodec,
        src: u16,
        dst: u16,
        mtype: u8,
        payload_plain: &[u8],
        fragmented: bool,
    ) -> Result<(), NetError> {
        self.seq_out += 1;
        let seq32 = (self.seq_out % (u32::MAX as u64)) as u32;
        let mut base_flags = 0u8;
        if fragmented {
            base_flags |= sakura_npp::frame::FLAG_FRAGMENT;
        }
        let (payload, flags) = match (&self.session_key, self.established) {
            (Some(key), true) => {
                let iv = self.mgm_iv(self.seq_out);
                let aad = Self::aad_for(
                    src,
                    dst,
                    seq32,
                    mtype,
                    base_flags | sakura_npp::frame::FLAG_ENCRYPTED,
                );
                let ct = sakura_hybrid::mgm_encrypt(key, &iv, &aad, payload_plain)
                    .map_err(|_| NetError::Crypto)?;
                (ct, base_flags | sakura_npp::frame::FLAG_ENCRYPTED)
            }
            _ => (payload_plain.to_vec(), base_flags),
        };
        let frame = Frame { src, dst, seq: seq32, msg_type: msg_type_of(mtype), flags, payload };
        let wire = codec.encode(&frame).map_err(NetError::Frame)?;
        let len = (wire.len() as u32).to_be_bytes();
        self.stream.write_all(&len).map_err(|_| NetError::Io)?;
        self.stream.write_all(&wire).map_err(|_| NetError::Io)?;
        self.stream.flush().map_err(|_| NetError::Io)
    }

    /// Чтение доступных кадров (неблокирующее, до max кадров).
    pub fn poll_frames(&mut self, codec: &NppCodec, max: usize) -> Result<Vec<(MsgType, u32, Vec<u8>)>, NetError> {
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => return Err(NetError::Closed),
            Ok(n) => {
                self.rx_buf.extend_from_slice(&chunk[..n]);
                self.last_rx_ms = sakura_common::time::unix_ms();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return Err(NetError::Io),
        }
        let mut out = Vec::new();
        loop {
            if self.rx_buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.rx_buf[..4].try_into().unwrap()) as usize;
            if len > sakura_npp::frame::MAX_FRAME_LEN {
                return Err(NetError::Frame(FrameError::Npp(NppErrCode::InvalidFrame)));
            }
            if self.rx_buf.len() < 4 + len {
                break;
            }
            let wire: Vec<u8> = self.rx_buf.drain(..4 + len).collect();
            let decoded = codec.decode(&wire[4..]).map_err(NetError::Frame)?;
            let f = decoded.frame;
            // anti-replay (§13.17): seq-окно на соединение
            self.replay.check_seq(f.seq as u64).map_err(NetError::Replay)?;
            let mtype = f.msg_type as u8;
            let plain = if f.flags & sakura_npp::frame::FLAG_ENCRYPTED != 0 {
                if !self.established {
                    return Err(NetError::Handshake(NppErrCode::SessionExpired));
                }
                let key = self.session_key.ok_or(NetError::Crypto)?;
                let iv = self.rx_iv(f.seq);
                let aad = Self::aad_for(
                    f.src,
                    f.dst,
                    f.seq,
                    mtype,
                    f.flags & (sakura_npp::frame::FLAG_ENCRYPTED | sakura_npp::frame::FLAG_FRAGMENT),
                );
                sakura_hybrid::mgm_decrypt(&key, &iv, &aad, &f.payload).map_err(|_| NetError::Crypto)?
            } else {
                f.payload.clone()
            };
            if f.flags & sakura_npp::frame::FLAG_FRAGMENT != 0 {
                // реассемблинг (§13.3: FRAGMENT_TIMEOUT при неполной сборке)
                let now = sakura_common::time::unix_ms();
                match self.reasm.lock_frame(f.src, mtype, &plain, now) {
                    Ok(Some(full)) => out.push((f.msg_type, f.seq, full)),
                    Ok(None) => {}
                    Err(_) => {
                        return Err(NetError::Frame(FrameError::Npp(NppErrCode::FragmentTimeout)))
                    }
                }
            } else {
                out.push((f.msg_type, f.seq, plain));
            }
            if out.len() >= max {
                break;
            }
        }
        Ok(out)
    }

    fn rx_iv(&self, seq32: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[1] = 1 - self.direction(); // входящее направление
        iv[2..10].copy_from_slice(&(seq32 as u64).to_be_bytes());
        iv
    }
}

fn msg_type_of(v: u8) -> MsgType {
    MsgType::from_u8(v).unwrap_or(MsgType::Error)
}

// ---------------- серверная/клиентская сторона рукопожатия ----------------

/// Проверка сертификата участника (из trust bundle) по TrustAnchor:
/// usage + subject_id + цепочка + CRL + время.
pub fn verify_peer_cert(
    anchor: &TrustAnchor,
    platform_cert: &SignerCert,
    info: &HelloInfo,
    cert: &SignerCert,
    now_s: u64,
) -> Result<(), NetError> {
    let expected_usage = match info.kind {
        PrincipalKind::Node => USAGE_DEVICE_IDENTITY,
        PrincipalKind::Operator => USAGE_OPERATOR,
    };
    if cert.key_usage != expected_usage {
        return Err(NetError::Handshake(NppErrCode::AuthFailed));
    }
    if cert.subject_id != info.id {
        return Err(NetError::Handshake(NppErrCode::AuthFailed));
    }
    let chain = vec![cert.clone(), platform_cert.clone()];
    anchor
        .verify_chain_for_usage(&chain, &cert.subject_id, Some(now_s))
        .map_err(|_| NetError::Handshake(NppErrCode::AuthFailed))?;
    Ok(())
}

/// Клиентская сторона: построить HELLO (подпись будет в AUTH_RESPONSE).
pub fn client_hello(id: [u8; 16], kind: PrincipalKind, hw_rev: u16) -> (Vec<u8>, [u8; 32]) {
    let mut nonce = [0u8; 32];
    sakura_common::rand::fill(&mut nonce);
    (hello_payload(kind, id, nonce, hw_rev), nonce)
}

/// Общий вывод сеансового ключа (§23.3.2 combiner + channel binding).
pub fn derive_session_key(h0: &[u8], h1: &[u8], h2: &[u8], h3: &[u8], ss_gost: &[u8], ss_pq: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut t = Vec::new();
    t.extend_from_slice(h0);
    t.extend_from_slice(h1);
    t.extend_from_slice(h2);
    t.extend_from_slice(h3);
    let salt = streebog256(&t);
    let keyb = hybrid_kem_combine(ss_gost, ss_pq, &salt, PROTOCOL_ID, 1);
    let mut key = [0u8; 32];
    key.copy_from_slice(&keyb);
    (key, salt) // salt = channel binding (§13.17)
}

/// Слушающий сокет с таймаутом accept.
pub fn listener(addr: &str) -> Result<TcpListener, NetError> {
    let l = TcpListener::bind(addr).map_err(|_| NetError::Io)?;
    l.set_nonblocking(true).map_err(|_| NetError::Io)?;
    Ok(l)
}

pub fn connect(addr: &str) -> Result<TcpStream, NetError> {
    let s = TcpStream::connect(addr).map_err(|_| NetError::Io)?;
    Ok(s)
}
