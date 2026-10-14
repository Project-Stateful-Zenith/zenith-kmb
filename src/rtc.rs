use crate::decode::{DecodeError, Reader};
use crate::time::KmbTime;

const NAME: &str = "rtc";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rtc {
    pub time: KmbTime,
    pub extra: Option<u64>,
}

impl Rtc {
    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(NAME, payload);
        if r.u16()? != 1 {
            return Err(DecodeError::Invalid {
                structure: NAME,
                reason: "tag is not 1",
            });
        }
        let time = r.time()?;
        let extra = if payload.len() >= 18 {
            Some(u64::from_be_bytes(r.array()?))
        } else {
            None
        };
        Ok(Self { time, extra })
    }
}
