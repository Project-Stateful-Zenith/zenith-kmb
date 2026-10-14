pub mod uni;

use crate::command::cmd;
use crate::decode::{DecodeError, Reader};
use crate::frame::Frame;
use crate::time::KmbTime;
use std::ops::Range;

pub mod kind {
    pub const MAIN: u8 = 0;
    pub const S_PROFILE: u8 = 1;
    pub const M_PROFILE: u8 = 2;
    pub const LOG: u8 = 3;
    pub const PQ_MAIN: u8 = 4;
    pub const PQ_EVENTS: u8 = 5;
    pub const ELMER: u8 = 6;
    pub const PMAX: u8 = 7;
    pub const PQ_OSCILLOGRAM: u8 = 8;
    pub const PQ_EVENT_TREND: u8 = 9;
    pub const HDO: u8 = 10;
    pub const GO: u8 = 11;
    pub const SMP_MODBUS_MASTER: u8 = 12;
    pub const MODBUS_MASTER: u8 = 13;
    pub const HISTOGRAM: u8 = 14;
    pub const UNBALANCE: u8 = 15;
    pub const EVENT_LOG: u8 = 16;
    pub const TREND: u8 = 17;
    pub const AVG: u8 = 18;
    pub const H2M: u8 = 24;
    pub const LB: u8 = 25;
    pub const LB2: u8 = 26;
    pub const DEBUG: u8 = 50;
}

pub const REPLY_HEADER_LEN: usize = 15;

pub const LAST_RECORD_TIME: KmbTime = KmbTime(252_455_616_000_000);
pub const FIRST_RECORD_TIME: KmbTime = KmbTime(0);

#[must_use]
pub fn request(address: u8, archive: u8, start: u32, per_frame: u16, frames: u8) -> Frame {
    let mut p = vec![archive];
    p.extend_from_slice(&start.to_be_bytes());
    p.extend_from_slice(&per_frame.to_be_bytes());
    p.push(frames.saturating_sub(1));
    Frame::new(address, cmd::GET_RECORD, p)
}

#[must_use]
pub fn probe(address: u8, archive: u8) -> Frame {
    request(address, archive, 0, 0, 1)
}

#[must_use]
pub fn request_part(address: u8, archive: u8, slot: u32, pos: u16, len: u16) -> Frame {
    let mut f = request(address, archive, slot, 1, 1);
    f.payload.extend_from_slice(&pos.to_be_bytes());
    f.payload.extend_from_slice(&len.to_be_bytes());
    f
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub max_rec: u32,
    pub cur_rec: i32,
}

impl Cursor {
    #[must_use]
    pub fn runs(&self) -> Vec<Range<u32>> {
        match self.cur_rec {
            0 => vec![],
            c if c > 0 => std::iter::once(0..c.unsigned_abs().min(self.max_rec)).collect(),
            c => {
                let Some(p) = self.max_rec.checked_sub(c.unsigned_abs()) else {
                    return vec![];
                };
                [p.saturating_add(1)..self.max_rec, 0..p]
                    .into_iter()
                    .filter(|r| !r.is_empty())
                    .collect()
            }
        }
    }

    #[must_use]
    pub fn runs_from(&self, slot: u32) -> Vec<Range<u32>> {
        let mut runs = self.runs().into_iter().skip_while(|r| !r.contains(&slot));
        let Some(first) = runs.next() else {
            return vec![];
        };
        std::iter::once(slot..first.end).chain(runs).collect()
    }

    #[must_use]
    pub fn len(&self) -> u32 {
        self.runs()
            .iter()
            .map(|r| r.end.saturating_sub(r.start))
            .fold(0, u32::saturating_add)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyHeader {
    pub archive: u8,
    pub unknown: [u8; 6],
    pub cursor: Cursor,
}

impl ReplyHeader {
    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new("archive reply", payload);
        let archive = r.u8()?;
        let unknown = r.array()?;
        let max_rec = r.u32()?;
        let cur_rec = i32::from_be_bytes(r.array()?);
        Ok(Self {
            archive,
            unknown,
            cursor: Cursor { max_rec, cur_rec },
        })
    }
}

pub fn records(payload: &[u8], record_len: usize) -> impl Iterator<Item = &[u8]> {
    let body = payload.get(REPLY_HEADER_LEN..).unwrap_or(&[]);
    body.chunks_exact(record_len.max(1))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordAtTime {
    pub slot: Option<u32>,
    pub time: KmbTime,
}

impl RecordAtTime {
    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new("record by time", payload);
        let cur = i32::from_be_bytes(r.array()?);
        let time = r.time()?;
        Ok(Self {
            slot: u32::try_from(cur).ok(),
            time,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub per_frame: u16,
    pub frames: u8,
}

pub const DEFAULT_COMM_BUF_LEN: u32 = 7200;
pub const DEFAULT_ARC_REPLY_CNT: u32 = 10;

impl Geometry {
    #[must_use]
    pub fn uni(comm_buf_len: u32, arc_reply_cnt: u32, record_len: usize, one_frame: bool) -> Self {
        let budget = usize::try_from(comm_buf_len.saturating_sub(50)).unwrap_or(usize::MAX);
        let per_frame = budget.checked_div(record_len.max(1)).unwrap_or(0);
        let frames = if one_frame {
            1
        } else {
            u8::try_from(arc_reply_cnt.max(1)).unwrap_or(u8::MAX)
        };
        Self {
            per_frame: u16::try_from(per_frame.max(1)).unwrap_or(u16::MAX),
            frames,
        }
    }

    #[must_use]
    pub fn batches(&self, run: Range<u32>) -> Vec<(u32, Self)> {
        let whole = Self {
            per_frame: self.per_frame.max(1),
            frames: self.frames.max(1),
        };
        let per = u32::from(whole.per_frame);
        let full = per.saturating_mul(u32::from(whole.frames));
        let mut out = Vec::new();
        let mut start = run.start;
        while start < run.end {
            let left = run.end.saturating_sub(start);
            let g = if left >= full {
                whole
            } else if left >= per {
                Self {
                    per_frame: whole.per_frame,
                    frames: u8::try_from(left.checked_div(per).unwrap_or(1)).unwrap_or(u8::MAX),
                }
            } else {
                Self {
                    per_frame: u16::try_from(left).unwrap_or(u16::MAX),
                    frames: 1,
                }
            };
            out.push((start, g));
            start =
                start.saturating_add(u32::from(g.per_frame).saturating_mul(u32::from(g.frames)));
        }
        out
    }
}
