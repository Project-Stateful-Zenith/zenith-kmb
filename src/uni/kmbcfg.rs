use super::{Description, END, Field, Group, Value, text};
use crate::decode::{DecodeError, Reader};

const NAME: &str = "kmbcfg";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Wire,
    Stored,
}

pub fn parse(bytes: &[u8]) -> Result<(Description, Dialect), DecodeError> {
    let mut r = Reader::new(NAME, bytes);
    let l1 = usize::from(r.u16()?);
    let mut gs = Reader::new(NAME, r.take(l1)?);
    let mut groups = Vec::new();
    loop {
        match gs.u8()? {
            END => break,
            idx => {
                let idxs = gs.u8()?;
                let name = text::read_short(&mut gs, text::SHORT_MAX)?;
                if !name.is_empty() {
                    groups.push(Group { idx, idxs, name });
                }
            }
        }
    }
    let l2 = usize::from(r.u16()?);
    let section = r.take(l2)?;
    let mut fs = Reader::new(NAME, section);
    let mut fields = Vec::new();
    while fs.position().saturating_add(3) < l2 {
        let name = text::read_short(&mut fs, text::SHORT_MAX)?;
        let ic = fs.u8()?;
        let type_code = fs.u8()?;
        let pb = fs.u16()?;
        let store = fs.u8()? & 0x0F;
        if !name.is_empty() {
            fields.push(Field {
                name,
                ic,
                type_code,
                pb,
                store,
            });
        }
    }
    let stream = r.take(r.remaining())?;
    let wire: usize = fields.iter().map(Field::width).sum();
    let stored: usize = fields
        .iter()
        .filter(|f| f.store > 0)
        .map(Field::width)
        .sum();
    let dialect = if stream.len() == wire {
        Dialect::Wire
    } else if stream.len() == stored {
        Dialect::Stored
    } else {
        return Err(DecodeError::Invalid {
            structure: NAME,
            reason: "value stream fits neither dialect",
        });
    };
    let mut vs = Reader::new(NAME, stream);
    let values = fields
        .iter()
        .map(|f| {
            if dialect == Dialect::Stored && f.store == 0 {
                Ok(None)
            } else {
                Value::read(&mut vs, f.typ(), f.pb).map(Some)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        Description {
            groups,
            fields,
            values,
        },
        dialect,
    ))
}

pub fn write(desc: &Description, dialect: Dialect) -> Result<Vec<u8>, DecodeError> {
    let mut groups = Vec::new();
    for g in &desc.groups {
        groups.extend_from_slice(&[g.idx, g.idxs]);
        text::write_short(&mut groups, &g.name, text::SHORT_MAX);
    }
    groups.push(END);
    let mut fields = Vec::new();
    for f in &desc.fields {
        text::write_short(&mut fields, &f.name, text::SHORT_MAX);
        fields.extend_from_slice(&[f.ic, f.type_code]);
        fields.extend_from_slice(&f.pb.to_be_bytes());
        fields.push(f.store);
    }
    let too_long = DecodeError::Invalid {
        structure: NAME,
        reason: "section over 65535 bytes",
    };
    let mut out = Vec::new();
    out.extend_from_slice(
        &u16::try_from(groups.len())
            .map_err(|_| too_long.clone())?
            .to_be_bytes(),
    );
    out.extend_from_slice(&groups);
    out.extend_from_slice(
        &u16::try_from(fields.len())
            .map_err(|_| too_long)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&fields);
    for (i, f) in desc.fields.iter().enumerate() {
        if dialect == Dialect::Stored && f.store == 0 {
            continue;
        }
        let missing = DecodeError::Invalid {
            structure: NAME,
            reason: "a field has no value",
        };
        let v = desc.values.get(i).and_then(Option::as_ref).ok_or(missing)?;
        v.write(&mut out, f.typ(), f.pb)?;
    }
    Ok(out)
}
