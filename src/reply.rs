use crate::frame::Frame;
use std::fmt;

pub const ERROR_FLAG: u8 = 0x80;

pub const NO_DATA: [u8; 2] = *b"Un";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    NoPermission,
    EncryptionRequired,
    KeyInvalid,
    Other(u8),
}

impl From<u8> for ErrorCode {
    fn from(code: u8) -> Self {
        match code {
            8 => Self::NoPermission,
            9 => Self::EncryptionRequired,
            10 => Self::KeyInvalid,
            other => Self::Other(other),
        }
    }
}

impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::NoPermission => 8,
            ErrorCode::EncryptionRequired => 9,
            ErrorCode::KeyInvalid => 10,
            ErrorCode::Other(other) => other,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPermission => f.write_str("no permission (8)"),
            Self::EncryptionRequired => f.write_str("encryption required (9)"),
            Self::KeyInvalid => f.write_str("encryption key invalid (10)"),
            Self::Other(code) => write!(f, "error code {code}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply<'a> {
    Data(&'a [u8]),
    NoData,
    Error {
        command: u8,
        code: ErrorCode,
        data: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyReply;

impl fmt::Display for EmptyReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reply frame has an empty payload")
    }
}

impl std::error::Error for EmptyReply {}

impl Frame {
    pub fn reply(&self) -> Result<Reply<'_>, EmptyReply> {
        let (&first, rest) = self.payload.split_first().ok_or(EmptyReply)?;
        if let Some(command) = self.command.checked_sub(ERROR_FLAG) {
            return Ok(Reply::Error {
                command,
                code: ErrorCode::from(first),
                data: rest,
            });
        }
        if self.payload == NO_DATA {
            return Ok(Reply::NoData);
        }
        Ok(Reply::Data(&self.payload))
    }

    #[must_use]
    pub fn is_ack(&self) -> bool {
        self.command < ERROR_FLAG && self.payload == [0]
    }
}
