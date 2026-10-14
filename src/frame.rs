use crate::crc::crc16;
use std::fmt;

pub const HEADER_LEN: usize = 4;
pub const CRC_LEN: usize = 2;
pub const MAX_PAYLOAD_LEN: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub address: u8,
    pub command: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    PayloadTooLong(usize),
    TooShort(usize),
    LengthMismatch { declared: usize, actual: usize },
    OverLimit { declared: usize, limit: usize },
    BadCrc { stored: u16, computed: u16 },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLong(n) => write!(f, "payload of {n} bytes exceeds 65535"),
            Self::TooShort(n) => write!(f, "frame of {n} bytes is shorter than 6"),
            Self::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "frame declares {declared} payload bytes but is {actual} bytes long"
                )
            }
            Self::OverLimit { declared, limit } => {
                write!(
                    f,
                    "frame declares {declared} payload bytes, limit is {limit}"
                )
            }
            Self::BadCrc { stored, computed } => {
                write!(f, "CRC {stored:#06X} stored, {computed:#06X} computed")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    pub fn new(address: u8, command: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            address,
            command,
            payload: payload.into(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let n = self.payload.len();
        let len = u16::try_from(n).map_err(|_| FrameError::PayloadTooLong(n))?;
        let mut out = Vec::with_capacity(usize::from(len).saturating_add(HEADER_LEN + CRC_LEN));
        out.push(self.address);
        out.extend_from_slice(&len.to_be_bytes());
        out.push(self.command);
        out.extend_from_slice(&self.payload);
        let crc = crc16(&out);
        out.extend_from_slice(&crc.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let too_short = || FrameError::TooShort(bytes.len());
        let (body, crc) = bytes.split_last_chunk::<CRC_LEN>().ok_or_else(too_short)?;
        let (header, payload) = body
            .split_first_chunk::<HEADER_LEN>()
            .ok_or_else(too_short)?;
        let [address, len_hi, len_lo, command] = *header;
        let declared = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if payload.len() != declared {
            return Err(FrameError::LengthMismatch {
                declared,
                actual: bytes.len(),
            });
        }
        let stored = u16::from_be_bytes(*crc);
        let computed = crc16(body);
        if stored != computed {
            return Err(FrameError::BadCrc { stored, computed });
        }
        Ok(Self::new(address, command, payload))
    }
}

#[derive(Debug)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    max_payload: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self::with_max_payload(MAX_PAYLOAD_LEN)
    }

    #[must_use]
    pub const fn with_max_payload(max_payload: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_payload,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn next_frame(&mut self) -> Option<Result<Frame, FrameError>> {
        let &[_, len_hi, len_lo, _] = self.buf.first_chunk::<HEADER_LEN>()?;
        let declared = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if declared > self.max_payload {
            self.buf.clear();
            return Some(Err(FrameError::OverLimit {
                declared,
                limit: self.max_payload,
            }));
        }
        let total = declared.saturating_add(HEADER_LEN + CRC_LEN);
        let result = Frame::decode(self.buf.get(..total)?);
        if result.is_ok() {
            self.buf.drain(..total);
        } else {
            self.buf.clear();
        }
        Some(result)
    }
}
