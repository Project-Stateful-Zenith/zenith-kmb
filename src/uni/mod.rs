pub mod kmbcfg;
pub mod text;
pub mod value;

pub use value::{TypeCode, Value};

use crate::decode::{DecodeError, Reader};
use crate::frame::Frame;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataSet {
    Config,
    Status,
    ActData,
    Archive,
    AvgData,
    MaxData,
    MinData,
    MaxDataT,
    MinDataT,
    Edata,
    Cal,
}

impl DataSet {
    #[must_use]
    pub const fn get_command(self) -> u8 {
        match self {
            Self::Config => 112,
            Self::ActData => 114,
            Self::Archive => 116,
            Self::Status => 118,
            Self::AvgData | Self::MaxData | Self::MinData | Self::MaxDataT | Self::MinDataT => 120,
            Self::Edata => 122,
            Self::Cal => 124,
        }
    }

    #[must_use]
    pub const fn set_command(self) -> u8 {
        match self {
            Self::Config => 113,
            Self::ActData => 115,
            Self::Archive => 117,
            Self::Status => 119,
            Self::AvgData | Self::MaxData | Self::MinData | Self::MaxDataT | Self::MinDataT => 121,
            Self::Edata => 123,
            Self::Cal => 125,
        }
    }

    #[must_use]
    pub const fn cm_typ(self) -> u8 {
        match self {
            Self::MaxData => 1,
            Self::MinData => 2,
            Self::MaxDataT => 3,
            Self::MinDataT => 4,
            _ => 0,
        }
    }
}

pub mod rezim {
    pub const GROUPS: u8 = 0;
    pub const FIELDS: u8 = 1;
    pub const VALUES: u8 = 2;
    pub const WRITE: u8 = 3;
    pub const COMMIT: u8 = 4;
    pub const CHANGE_COUNTER: u8 = 5;
}

pub const COUNT_R_ALL: u16 = 65000;
pub const WRITE_BUDGET: usize = 1400;
pub const END: u8 = 0xFF;

#[must_use]
pub fn get(address: u8, pin: u32, set: DataSet, rezim: u8, start: u16, count_r: u16) -> Frame {
    let mut p = Vec::with_capacity(17);
    p.extend_from_slice(&pin.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, set.cm_typ(), rezim]);
    p.extend_from_slice(&start.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&count_r.to_be_bytes());
    Frame::new(address, set.get_command(), p)
}

#[must_use]
pub fn set(
    address: u8,
    pin: u32,
    command: u8,
    rezim: u8,
    start: u16,
    count: u16,
    data: &[u8],
) -> Frame {
    let mut p = Vec::with_capacity(data.len().saturating_add(17));
    p.extend_from_slice(&pin.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, rezim]);
    p.extend_from_slice(&start.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(&COUNT_R_ALL.to_be_bytes());
    p.extend_from_slice(data);
    Frame::new(address, command, p)
}

#[must_use]
pub fn commit(address: u8, pin: u32, changed_groups: &[u8]) -> Frame {
    let mut data = changed_groups.to_vec();
    data.push(END);
    set(
        address,
        pin,
        DataSet::Config.set_command(),
        rezim::COMMIT,
        0,
        0,
        &data,
    )
}

#[must_use]
pub fn clear_archives(address: u8, pin: u32, archive_groups: &[u8]) -> Frame {
    let mut data = archive_groups.to_vec();
    data.push(END);
    set(
        address,
        pin,
        DataSet::Archive.set_command(),
        rezim::COMMIT,
        0,
        0,
        &data,
    )
}

pub const fn change_counter(payload: &[u8]) -> Result<u8, DecodeError> {
    match payload {
        [b] => Ok(*b),
        _ => Err(DecodeError::Length {
            structure: "change counter",
            len: payload.len(),
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub start: u16,
    pub count: u16,
    pub total: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    More(u16),
    Done,
}

impl Cursor {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            start: r.u16()?,
            count: r.u16()?,
            total: r.u16()?,
        })
    }

    pub fn page(self, structure: &'static str) -> Result<Page, DecodeError> {
        let end = self.start.checked_add(self.count);
        match end.map(|end| (end, end.cmp(&self.total))) {
            Some((end, std::cmp::Ordering::Less)) => Ok(Page::More(end)),
            Some((_, std::cmp::Ordering::Equal)) => Ok(Page::Done),
            Some((_, std::cmp::Ordering::Greater)) | None => Err(DecodeError::Invalid {
                structure,
                reason: "cursor runs past the total",
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub idx: u8,
    pub idxs: u8,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ic: u8,
    pub type_code: u8,
    pub pb: u16,
    pub store: u8,
}

impl Field {
    #[must_use]
    pub const fn typ(&self) -> TypeCode {
        TypeCode::from_wire(self.type_code)
    }

    #[must_use]
    pub fn width(&self) -> usize {
        self.typ().width(self.pb)
    }

    #[must_use]
    pub fn short_name(&self) -> &str {
        self.name.split('|').next().unwrap_or(&self.name)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ArchiveGroup {
    pub idx: u8,
    pub idxs: u8,
    pub idxss: u8,
    pub typ: u16,
    pub k: f32,
    pub unit: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveField {
    pub name: String,
    pub ic: u8,
    pub ics: u8,
    pub icss: u8,
    pub info1: u8,
    pub info2: u8,
    pub type_code: u8,
    pub pb: u16,
    pub zapis: u8,
    pub zapis2: Option<Vec<u8>>,
}

impl ArchiveField {
    #[must_use]
    pub const fn typ(&self) -> TypeCode {
        TypeCode::from_wire(self.type_code)
    }
}

fn read_group(r: &mut Reader<'_>, idx: u8) -> Result<Group, DecodeError> {
    let idxs = r.u8()?;
    let name = text::read_short(r, text::SHORT_MAX)?;
    Ok(Group { idx, idxs, name })
}

fn read_field(r: &mut Reader<'_>) -> Result<Field, DecodeError> {
    let name = text::read_short(r, text::SHORT_MAX)?;
    let ic = r.u8()?;
    let type_code = r.u8()?;
    let pb = r.u16()?;
    let store = r.u8()? & 0x0F;
    Ok(Field {
        name,
        ic,
        type_code,
        pb,
        store,
    })
}

fn read_archive_group(r: &mut Reader<'_>, idx: u8) -> Result<ArchiveGroup, DecodeError> {
    let idxs = r.u8()?;
    let idxss = r.u8()?;
    let typ = r.u16()?;
    let k = f32::from_be_bytes(r.array()?);
    let unit = text::read_short(r, text::SHORT_MAX)?;
    let name = text::read_short(r, text::SHORT_MAX)?;
    Ok(ArchiveGroup {
        idx,
        idxs,
        idxss,
        typ,
        k,
        unit,
        name,
    })
}

fn read_archive_field(r: &mut Reader<'_>) -> Result<ArchiveField, DecodeError> {
    let name = text::read_short(r, text::ARCHIVE_NAME_MAX)?;
    let ic = r.u8()?;
    let ics = r.u8()?;
    let icss = r.u8()?;
    let info1 = r.u8()?;
    let info2 = r.u8()?;
    let type_code = r.u8()?;
    let pb = r.u16()?;
    let zapis = r.u8()?;
    let zapis2 = if info2 == 200 || (20..=29).contains(&info2) {
        let m = r.u8()?;
        Some(r.take(usize::from(m))?.to_vec())
    } else {
        None
    };
    Ok(ArchiveField {
        name,
        ic,
        ics,
        icss,
        info1,
        info2,
        type_code,
        pb,
        zapis,
        zapis2,
    })
}

fn read_until_end<T>(
    r: &mut Reader<'_>,
    mut read: impl FnMut(&mut Reader<'_>, u8) -> Result<T, DecodeError>,
) -> Result<Vec<T>, DecodeError> {
    let mut out = Vec::new();
    loop {
        match r.u8()? {
            END => return Ok(out),
            idx => out.push(read(r, idx)?),
        }
    }
}

pub fn parse_groups(payload: &[u8]) -> Result<(Cursor, Vec<Group>), DecodeError> {
    let mut r = Reader::new("groups", payload);
    let cursor = Cursor::read(&mut r)?;
    let mut groups = read_until_end(&mut r, read_group)?;
    groups.retain(|g| !g.name.is_empty());
    Ok((cursor, groups))
}

pub fn parse_fields(payload: &[u8]) -> Result<(Cursor, Vec<Field>), DecodeError> {
    let mut r = Reader::new("fields", payload);
    let cursor = Cursor::read(&mut r)?;
    let mut fields = (0..cursor.count)
        .map(|_| read_field(&mut r))
        .collect::<Result<Vec<_>, _>>()?;
    fields.retain(|f| !f.name.is_empty());
    Ok((cursor, fields))
}

pub fn parse_archive_groups(payload: &[u8]) -> Result<(Cursor, Vec<ArchiveGroup>), DecodeError> {
    let mut r = Reader::new("archive groups", payload);
    let cursor = Cursor::read(&mut r)?;
    let mut groups = read_until_end(&mut r, read_archive_group)?;
    groups.retain(|g| !g.name.is_empty());
    Ok((cursor, groups))
}

pub fn parse_archive_fields(payload: &[u8]) -> Result<(Cursor, Vec<ArchiveField>), DecodeError> {
    let mut r = Reader::new("archive fields", payload);
    let cursor = Cursor::read(&mut r)?;
    let mut fields = (0..cursor.count)
        .map(|_| read_archive_field(&mut r))
        .collect::<Result<Vec<_>, _>>()?;
    fields.retain(|f| !f.name.is_empty());
    Ok((cursor, fields))
}

fn append_page<T>(
    held: &mut Vec<T>,
    cursor: Cursor,
    items: Vec<T>,
    structure: &'static str,
    total_zero_ok: bool,
) -> Result<Page, DecodeError> {
    if cursor.start == 0 {
        held.clear();
    }
    let gate = DecodeError::Invalid {
        structure,
        reason: "page does not continue the list",
    };
    if held.len() != usize::from(cursor.start) {
        return Err(gate);
    }
    held.extend(items);
    let page = cursor.page(structure)?;
    if page == Page::Done
        && held.len() != usize::from(cursor.total)
        && !(total_zero_ok && cursor.total == 0)
    {
        return Err(DecodeError::Invalid {
            structure,
            reason: "list shorter than the total",
        });
    }
    Ok(page)
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Description {
    pub groups: Vec<Group>,
    pub fields: Vec<Field>,
    pub values: Vec<Option<Value>>,
}

impl Description {
    pub fn push_groups(&mut self, payload: &[u8]) -> Result<Page, DecodeError> {
        let (cursor, groups) = parse_groups(payload)?;
        append_page(&mut self.groups, cursor, groups, "groups", true)
    }

    pub fn push_fields(&mut self, payload: &[u8]) -> Result<Page, DecodeError> {
        let (cursor, fields) = parse_fields(payload)?;
        let page = append_page(&mut self.fields, cursor, fields, "fields", false)?;
        self.values.resize(self.fields.len(), None);
        Ok(page)
    }

    pub fn push_values(&mut self, payload: &[u8]) -> Result<Page, DecodeError> {
        const NAME: &str = "values";
        let beyond = || DecodeError::Invalid {
            structure: NAME,
            reason: "values beyond the fields",
        };
        let mut r = Reader::new(NAME, payload);
        let cursor = Cursor::read(&mut r)?;
        let start = usize::from(cursor.start);
        let end = start
            .checked_add(usize::from(cursor.count))
            .filter(|&end| end <= self.fields.len())
            .ok_or_else(beyond)?;
        self.values.resize(self.fields.len(), None);
        let fields = self.fields.get(start..end).ok_or_else(beyond)?;
        let slots = self.values.get_mut(start..end).ok_or_else(beyond)?;
        for (f, slot) in fields.iter().zip(slots) {
            *slot = Some(Value::read(&mut r, f.typ(), f.pb)?);
        }
        cursor.page(NAME)
    }

    #[must_use]
    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name == name)
    }

    #[must_use]
    pub fn field_index(&self, group: &str, name: &str) -> Option<usize> {
        let ic = self.group(group)?.idx;
        self.fields
            .iter()
            .position(|f| f.ic == ic && f.name == name)
    }

    #[must_use]
    pub fn value(&self, group: &str, name: &str) -> Option<&Value> {
        self.values.get(self.field_index(group, name)?)?.as_ref()
    }

    pub fn set_value(&mut self, group: &str, name: &str, value: Value) -> Result<u8, DecodeError> {
        let no_field = || DecodeError::Invalid {
            structure: "set value",
            reason: "no such field",
        };
        let i = self.field_index(group, name).ok_or_else(no_field)?;
        let f = self.fields.get(i).ok_or_else(no_field)?;
        value.write(&mut Vec::new(), f.typ(), f.pb)?;
        let ic = f.ic;
        self.values.resize(self.fields.len(), None);
        let slot = self.values.get_mut(i).ok_or_else(no_field)?;
        *slot = Some(value);
        Ok(ic)
    }

    #[must_use]
    pub fn chunk(&self, start: usize, budget: usize) -> std::ops::Range<usize> {
        let mut used: usize = 0;
        let mut end = start;
        for f in self.fields.iter().skip(start) {
            let w = f.typ().budget_width(f.pb);
            if end > start && used.saturating_add(w) > budget {
                break;
            }
            used = used.saturating_add(w);
            end = end.saturating_add(1);
        }
        start..end
    }

    pub fn write_chunks(
        &self,
        address: u8,
        pin: u32,
        set: DataSet,
    ) -> Result<Vec<Frame>, DecodeError> {
        self.write_chunks_range(address, pin, set, 0..self.fields.len())
    }

    #[must_use]
    pub fn group_range(&self, group: &str) -> Option<std::ops::Range<usize>> {
        let ic = self.group(group)?.idx;
        let start = self.fields.iter().position(|f| f.ic == ic)?;
        let from_start = self.fields.get(start..)?;
        let len = from_start.iter().take_while(|f| f.ic == ic).count();
        let rest = from_start.get(len..)?.iter().any(|f| f.ic == ic);
        let end = start.checked_add(len)?;
        (!rest).then_some(start..end)
    }

    pub fn write_chunks_range(
        &self,
        address: u8,
        pin: u32,
        set: DataSet,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<Frame>, DecodeError> {
        let end = range.end.min(self.fields.len());
        let invalid = |reason| DecodeError::Invalid {
            structure: "write",
            reason,
        };
        let mut frames = Vec::new();
        let mut start = range.start;
        while start < end {
            let range = self.chunk(start, WRITE_BUDGET);
            let range = range.start..range.end.min(end);
            let fields = self
                .fields
                .get(range.clone())
                .ok_or_else(|| invalid("range beyond the fields"))?;
            let mut data = Vec::new();
            for (i, f) in range.clone().zip(fields) {
                let v = self
                    .values
                    .get(i)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| invalid("a field has no value"))?;
                v.write(&mut data, f.typ(), f.pb)?;
            }
            let too_many = |_| invalid("chunk start or count over 65535");
            frames.push(set_chunk(
                address,
                pin,
                set,
                u16::try_from(range.start).map_err(too_many)?,
                u16::try_from(range.len()).map_err(too_many)?,
                &data,
            ));
            start = range.end;
        }
        Ok(frames)
    }
}

fn set_chunk(address: u8, pin: u32, set_: DataSet, start: u16, count: u16, data: &[u8]) -> Frame {
    set(
        address,
        pin,
        set_.set_command(),
        rezim::WRITE,
        start,
        count,
        data,
    )
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ArchiveDescription {
    pub groups: Vec<ArchiveGroup>,
    pub fields: Vec<ArchiveField>,
}

impl ArchiveDescription {
    pub fn push_groups(&mut self, payload: &[u8]) -> Result<Page, DecodeError> {
        let (cursor, groups) = parse_archive_groups(payload)?;
        append_page(&mut self.groups, cursor, groups, "archive groups", true)
    }

    pub fn push_fields(&mut self, payload: &[u8]) -> Result<Page, DecodeError> {
        let (cursor, fields) = parse_archive_fields(payload)?;
        append_page(&mut self.fields, cursor, fields, "archive fields", false)
    }
}
