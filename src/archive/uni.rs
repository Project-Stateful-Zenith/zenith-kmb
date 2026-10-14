use crate::decode::{DecodeError, Reader};
use crate::time::KmbTime;
use crate::uni::value::{TypeCode, Value};
use crate::uni::{ArchiveDescription, ArchiveField, ArchiveGroup};
use std::fmt;

#[must_use]
pub const fn archive_name(archive: u8) -> Option<&'static str> {
    Some(match archive {
        0 => "Main",
        1 => "SProfile",
        2 => "MProfile",
        3 => "Log",
        4 => "MainPQ",
        5 => "PQevents",
        6 => "Elmeter",
        11 => "GO",
        13 => "Modbus Master",
        14 => "Histogram",
        15 => "Unbalance",
        16 => "Event Log",
        17 => "Trend",
        18 => "Avg",
        24 => "H2M",
        25 => "LB",
        26 => "LB2",
        _ => return None,
    })
}

#[must_use]
pub fn header_version(fields: &[ArchiveField], arch_ver: Option<u32>) -> u32 {
    let named = |i: usize, name: &str| fields.get(i).is_some_and(|f| f.name == name);
    let version = if named(3, "Ecc") {
        3
    } else if named(2, "AId") {
        2
    } else {
        u32::from(named(1, "Sum"))
    };
    match arch_ver {
        Some(v) if v > 3 => v,
        _ => version,
    }
}

#[must_use]
pub fn field_width(f: &ArchiveField) -> usize {
    match f.typ() {
        TypeCode::DateTime => 8,
        t => t.width(f.pb),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub field: ArchiveField,
    pub offset: usize,
    pub width: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Layout {
    pub archive: u8,
    pub group: ArchiveGroup,
    pub version: u32,
    pub slots: Vec<Slot>,
    pub record_len: usize,
    pub ecc_len: usize,
}

const fn header_names(version: u32) -> &'static [&'static str] {
    match version {
        0 => &["Length", "Time"],
        1 => &["Length", "Sum", "Time"],
        2 => &["Length", "Sum", "AId", "Time"],
        _ => &["Length", "Sum", "AId", "Ecc", "Time"],
    }
}

pub const DEFAULT_MAX_ARCH_SIZE: usize = 15000;

impl Layout {
    pub fn new(
        desc: &ArchiveDescription,
        archive: u8,
        version: u32,
        max_arch_size: usize,
    ) -> Result<Self, DecodeError> {
        let invalid = |reason| DecodeError::Invalid {
            structure: "archive layout",
            reason,
        };
        let name =
            archive_name(archive).ok_or_else(|| invalid("archive type has no universal name"))?;
        let group = desc
            .groups
            .iter()
            .find(|g| g.idxs == 0 && g.idxss == 0 && g.name == name)
            .ok_or_else(|| invalid("device does not offer this archive"))?
            .clone();
        if version > 4 {
            return Err(invalid("header version above 4"));
        }
        let mut slots = Vec::new();
        let mut offset = 0;
        for f in desc
            .fields
            .iter()
            .filter(|f| f.ic == group.idx && f.zapis != 0)
        {
            let width = field_width(f);
            slots.push(Slot {
                field: f.clone(),
                offset,
                width,
            });
            offset = offset
                .checked_add(width)
                .ok_or_else(|| invalid("record reaches MaxArchSize"))?;
        }
        let header = header_names(version);
        let matches = slots.len() >= header.len()
            && slots
                .iter()
                .zip(header)
                .all(|(s, name)| s.field.name == *name);
        if !matches {
            return Err(invalid("fields do not start with the record header"));
        }
        if offset >= max_arch_size {
            return Err(invalid("record reaches MaxArchSize"));
        }
        let ecc_len = if version >= 3 {
            slots.get(3).map_or(0, |s| s.width)
        } else {
            0
        };
        Ok(Self {
            archive,
            group,
            version,
            slots,
            record_len: offset,
            ecc_len,
        })
    }

    fn slot(&self, name: &str) -> Option<&Slot> {
        self.slots.iter().find(|s| s.field.name == name)
    }

    #[must_use]
    pub fn time_offset(&self) -> usize {
        self.slot("Time").map_or(0, |s| s.offset)
    }

    pub fn check(&self, record: &[u8]) -> Result<(), Reject> {
        let r = record;
        if r.len() != self.record_len {
            return Err(Reject::Length);
        }
        let be16 = |at: usize| -> Result<u16, Reject> {
            let bytes = r.get(at..).and_then(|b| b.first_chunk::<2>());
            bytes.map(|b| u16::from_be_bytes(*b)).ok_or(Reject::Length)
        };
        let length = be16(0)?;
        if self.version == 4 {
            if length == 0xFFFF {
                return Err(Reject::Erased);
            }
            if !ecc_ok(r, self.ecc_len) {
                return Err(Reject::Ecc);
            }
        }
        if (1..=4).contains(&self.version) && self.archive != super::kind::GO && sum(r) != be16(2)?
        {
            return Err(Reject::Sum);
        }
        if usize::from(length) != self.record_len {
            return Err(Reject::Length);
        }
        let time = self.time(r).ok_or(Reject::Length)?.0;
        match time {
            0 => Err(Reject::TimeZero),
            u64::MAX => Err(Reject::TimeInvalid),
            t if t > TIME_2100 => Err(Reject::TimeAfter2100),
            _ => Ok(()),
        }
    }

    pub fn decode(&self, record: &[u8]) -> Result<Vec<(String, Value)>, DecodeError> {
        if record.len() != self.record_len {
            return Err(DecodeError::Length {
                structure: "archive record",
                len: record.len(),
            });
        }
        let mut r = Reader::new("archive record", record);
        self.slots
            .iter()
            .map(|s| {
                let v = match s.field.typ() {
                    TypeCode::DateTime => Value::U64(u64::from_be_bytes(r.array()?)),
                    t => Value::read(&mut r, t, s.field.pb)?,
                };
                Ok((s.field.name.clone(), v))
            })
            .collect()
    }

    #[must_use]
    pub fn time(&self, record: &[u8]) -> Option<KmbTime> {
        let bytes = record.get(self.time_offset()..)?.first_chunk::<8>()?;
        Some(KmbTime::from_be_bytes(*bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stat {
    Avg,
    Min,
    Max,
}

impl Stat {
    #[must_use]
    pub const fn of(field: &ArchiveField) -> Option<Self> {
        match (field.info1, field.info2) {
            (0, 1) => Some(Self::Avg),
            (0, 2) => Some(Self::Min),
            (0, 3) => Some(Self::Max),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avg => "avg",
            Self::Min => "min",
            Self::Max => "max",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Column {
    pub name: String,
    pub stat: Option<Stat>,
    pub unit: String,
    pub k: f32,
}

impl Column {
    #[must_use]
    pub fn scaled(&self, value: &Value) -> Option<f64> {
        Some(value.as_f64()? * f64::from(self.k))
    }
}

impl Layout {
    #[must_use]
    pub fn columns(&self, desc: &ArchiveDescription) -> Vec<Column> {
        let find = |ics: u8, icss: u8| {
            desc.groups
                .iter()
                .find(|g| g.idx == self.group.idx && g.idxs == ics && g.idxss == icss)
        };
        self.slots
            .iter()
            .map(|s| {
                let f = &s.field;
                let sub = find(f.ics, 0).filter(|_| f.ics != 0);
                let subsub = find(f.ics, f.icss).filter(|_| f.icss != 0);
                let group = subsub.or(sub).unwrap_or(&self.group);
                let mut parts: Vec<&str> = [sub, subsub]
                    .into_iter()
                    .flatten()
                    .map(|g| g.name.as_str())
                    .collect();
                let (name, own_unit) = match f.name.split_once('[') {
                    Some((name, unit)) => (name, Some(unit)),
                    None => (f.name.as_str(), None),
                };
                parts.push(name);
                Column {
                    name: parts.join("_"),
                    stat: Stat::of(f),
                    unit: own_unit.unwrap_or(&group.unit).trim().to_string(),
                    k: group.k,
                }
            })
            .collect()
    }
}

const TIME_2100: u64 = 36_525 * 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Erased,
    Ecc,
    Sum,
    Length,
    TimeZero,
    TimeInvalid,
    TimeAfter2100,
}

impl Reject {
    #[must_use]
    pub const fn reason(self) -> u8 {
        match self {
            Self::Erased | Self::Ecc | Self::Sum => 16,
            Self::Length => 15,
            Self::TimeZero => 11,
            Self::TimeInvalid => 12,
            Self::TimeAfter2100 => 14,
        }
    }
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Erased => "erased slot",
            Self::Ecc => "ECC mismatch",
            Self::Sum => "Sum mismatch",
            Self::Length => "wrong length",
            Self::TimeZero => "time is 0",
            Self::TimeInvalid => "time is invalid",
            Self::TimeAfter2100 => "time after 2100",
        };
        f.write_str(text)
    }
}

impl std::error::Error for Reject {}

#[must_use]
pub fn sum(record: &[u8]) -> u16 {
    if record.len() < 12 {
        return 0;
    }
    let [l0, l1, _, _, body @ ..] = record else {
        return 0;
    };
    let mut s: u32 = 0;
    let (words, rest) = body.as_chunks::<4>();
    for w in words {
        s = s.wrapping_add(u32::from_le_bytes(*w));
    }
    for &b in rest {
        s = s.wrapping_add(u32::from(b));
    }
    let [b0, b1, b2, b3] = s.to_le_bytes();
    let f = u16::from_le_bytes([b0, b1]).wrapping_add(u16::from_le_bytes([b2, b3]));
    f.wrapping_add(u16::from(*l0)).wrapping_add(u16::from(*l1))
}

#[must_use]
pub fn ecc_block(block: &[u8; 512]) -> [u8; 3] {
    let mut rp = [[0u8; 2]; 9];
    let mut cp = [[0u8; 2]; 3];
    let flip = |[even, odd]: &mut [u8; 2], high: bool, p: u8| {
        if high {
            *odd ^= p;
        } else {
            *even ^= p;
        }
    };
    for (i, &x) in block.iter().enumerate() {
        let p = u8::from(x.count_ones() & 1 == 1);
        for (m, pair) in rp.iter_mut().enumerate() {
            flip(pair, (i >> m) & 1 == 1, p);
        }
        for j in (0..8).filter(|j| x >> j & 1 == 1) {
            for (k, pair) in cp.iter_mut().enumerate() {
                flip(pair, (j >> k) & 1 == 1, 1);
            }
        }
    }
    let code = rp
        .iter()
        .chain(&cp)
        .flatten()
        .enumerate()
        .fold(0u32, |acc, (n, &b)| acc | u32::from(b) << n);
    let [c0, c1, c2, _] = code.to_le_bytes();
    [!c0, !c1, !c2]
}

#[must_use]
pub fn ecc(record: &[u8], ecc_len: usize) -> Vec<u8> {
    let mut work = record.to_vec();
    for b in work.iter_mut().skip(2).take(2) {
        *b = 0;
    }
    for b in work.iter_mut().skip(8).take(ecc_len) {
        *b = 0;
    }
    let codes = ecc_len / 3;
    let blocks = work.chunks(512).map(|chunk| {
        let mut block = [0u8; 512];
        for (d, s) in block.iter_mut().zip(chunk) {
            *d = *s;
        }
        block
    });
    blocks
        .chain(std::iter::repeat([0u8; 512]))
        .take(codes)
        .flat_map(|block| ecc_block(&block))
        .collect()
}

fn ecc_ok(record: &[u8], ecc_len: usize) -> bool {
    if record.len() < 12 {
        return false;
    }
    let codes = ecc_len / 3;
    let Some(ecc_bytes) = record.get(8..).and_then(|r| r.get(..ecc_len)) else {
        return false;
    };
    let stored = ecc_bytes.as_chunks::<3>().0.as_flattened();
    if codes > (record.len() / 512).saturating_add(1) {
        return stored.iter().all(|&b| b == 0);
    }
    ecc(record, ecc_len) == *stored
}
