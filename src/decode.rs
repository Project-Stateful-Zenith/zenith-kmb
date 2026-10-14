use crate::time::KmbTime;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Length {
        structure: &'static str,
        len: usize,
    },
    Truncated {
        structure: &'static str,
    },
    Invalid {
        structure: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { structure, len } => {
                write!(
                    f,
                    "{structure}: payload of {len} bytes is not an accepted length"
                )
            }
            Self::Truncated { structure } => write!(f, "{structure}: payload is truncated"),
            Self::Invalid { structure, reason } => write!(f, "{structure}: {reason}"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    structure: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(structure: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            structure,
        }
    }

    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    const fn truncated(&self) -> DecodeError {
        DecodeError::Truncated {
            structure: self.structure,
        }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.truncated())?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| self.truncated())?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let field = self.take(N)?;
        <[u8; N]>::try_from(field).map_err(|_| self.truncated())
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        let [byte] = self.array()?;
        Ok(byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn time(&mut self) -> Result<KmbTime, DecodeError> {
        Ok(KmbTime::from_be_bytes(self.array()?))
    }

    pub(crate) fn string(&mut self, n: usize) -> Result<String, DecodeError> {
        Ok(kmb_string(self.take(n)?))
    }
}

#[must_use]
pub fn kmb_string(field: &[u8]) -> String {
    let text = field
        .iter()
        .position(|&b| b == 0)
        .and_then(|end| field.get(..end))
        .unwrap_or(field);
    String::from_utf8_lossy(text).into_owned()
}

#[must_use]
pub fn encode_kmb_string(text: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    for c in text.chars() {
        if out.len().saturating_add(c.len_utf8()) > n.saturating_sub(1) {
            break;
        }
        let mut buf = [0; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    out.resize(n, 0);
    out
}
