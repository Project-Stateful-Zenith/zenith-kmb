#![doc = include_str!("../docs/kmb.md")]
#![forbid(unsafe_code)]

pub mod archive;
pub mod command;
pub mod crc;
pub mod decode;
pub mod envelope;
pub mod frame;
pub mod identify;
pub mod pin;
pub mod reply;
pub mod rtc;
pub mod time;
pub mod uni;

pub use crc::crc16;
pub use decode::DecodeError;
pub use envelope::{EnvelopeError, Handshake, Psk};
pub use frame::{Frame, FrameDecoder, FrameError};
pub use identify::{Family, Identify};
pub use reply::{EmptyReply, ErrorCode, Reply};
pub use rtc::Rtc;
pub use time::KmbTime;
