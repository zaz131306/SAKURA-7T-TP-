//! sakura-npp — NPP Frame Format (§13.3, ICD-1, BC-26):
//!
//! ```text
//! | Preamble (8B) | SFD (1B) | Header (15B) | Payload (0–1500B)
//!   | Padding (var) | FEC (var) | CRC32 (4B) |
//! ```
//!
//! - [`frame`] — кодек кадра v2.3: CRC8 заголовка, CRC32 (IEEE 802.3),
//!   padding-выравнивание и FEC (BC-26), fail-secure детекция формата;
//! - [`rs`] — RS(544,514) GF(2¹⁰), t=15;
//! - [`gf1024`] — арифметика поля;
//! - [`replay`] — anti-replay окно (§13.17: Seq + timestamp + nonce);
//! - [`msg`] — типы сообщений и коды ошибок §13.3.
#![forbid(unsafe_code)]

pub mod frame;
pub mod gf1024;
pub mod msg;
pub mod payload;
pub mod replay;
pub mod rs;

pub use frame::{
    Frame, FrameDecodeOutcome, FrameError, FrameReassembler, NppCodec, ReassembleError,
    split_fragments, FRAG_UNIT,
};
pub use msg::{MsgType, NppErrCode};
pub use replay::ReplayWindow;
