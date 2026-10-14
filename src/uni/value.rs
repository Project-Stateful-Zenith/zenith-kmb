use super::text;
use crate::decode::{DecodeError, Reader};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypeCode {
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    S8,
    S16,
    S32,
    S64,
    U8Array,
    U16Array,
    U32Array,
    F32Array,
    F64Array,
    S8Array,
    S16Array,
    S32Array,
    String,
    DateTime,
}

impl TypeCode {
    #[must_use]
    pub const fn from_wire(code: u8) -> Self {
        match code {
            1 => Self::U16,
            2 => Self::U32,
            3 => Self::U64,
            4 => Self::F32,
            5 => Self::F64,
            6 => Self::S8,
            7 => Self::S16,
            8 => Self::S32,
            9 => Self::S64,
            10 => Self::U8Array,
            11 => Self::U16Array,
            12 => Self::U32Array,
            13 => Self::F32Array,
            14 => Self::F64Array,
            15 => Self::S8Array,
            16 => Self::S16Array,
            17 => Self::S32Array,
            18 => Self::String,
            19 => Self::DateTime,
            _ => Self::U8,
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::U8 => 0,
            Self::U16 => 1,
            Self::U32 => 2,
            Self::U64 => 3,
            Self::F32 => 4,
            Self::F64 => 5,
            Self::S8 => 6,
            Self::S16 => 7,
            Self::S32 => 8,
            Self::S64 => 9,
            Self::U8Array => 10,
            Self::U16Array => 11,
            Self::U32Array => 12,
            Self::F32Array => 13,
            Self::F64Array => 14,
            Self::S8Array => 15,
            Self::S16Array => 16,
            Self::S32Array => 17,
            Self::String => 18,
            Self::DateTime => 19,
        }
    }

    #[must_use]
    pub fn width(self, pb: u16) -> usize {
        let pb = usize::from(pb);
        match self {
            Self::U8 | Self::S8 => 1,
            Self::U16 | Self::S16 => 2,
            Self::U32 | Self::S32 | Self::F32 => 4,
            Self::U64 | Self::S64 | Self::F64 => 8,
            Self::U8Array | Self::S8Array | Self::String => pb,
            Self::U16Array | Self::S16Array => pb.saturating_mul(2),
            Self::U32Array | Self::S32Array | Self::F32Array => pb.saturating_mul(4),
            Self::F64Array => pb.saturating_mul(8),
            Self::DateTime => 0,
        }
    }

    #[must_use]
    pub fn budget_width(self, pb: u16) -> usize {
        match self {
            Self::DateTime => 1,
            other => other.width(pb),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    U8Array(Vec<u8>),
    U16Array(Vec<u16>),
    U32Array(Vec<u32>),
    F32Array(Vec<f32>),
    F64Array(Vec<f64>),
    S8Array(Vec<i8>),
    S16Array(Vec<i16>),
    S32Array(Vec<i32>),
    String(String),
    Empty,
}

const NAME: &str = "universal value";

fn array<T, const N: usize>(
    r: &mut Reader<'_>,
    pb: u16,
    f: fn([u8; N]) -> T,
) -> Result<Vec<T>, DecodeError> {
    (0..pb).map(|_| Ok(f(r.array()?))).collect()
}

impl Value {
    pub(crate) fn read(r: &mut Reader<'_>, typ: TypeCode, pb: u16) -> Result<Self, DecodeError> {
        use TypeCode as T;
        Ok(match typ {
            T::U8 => Self::U8(r.u8()?),
            T::U16 => Self::U16(r.u16()?),
            T::U32 => Self::U32(r.u32()?),
            T::U64 => Self::U64(u64::from_be_bytes(r.array()?)),
            T::F32 => Self::F32(f32::from_be_bytes(r.array()?)),
            T::F64 => Self::F64(f64::from_be_bytes(r.array()?)),
            T::S8 => Self::S8(i8::from_be_bytes(r.array()?)),
            T::S16 => Self::S16(i16::from_be_bytes(r.array()?)),
            T::S32 => Self::S32(i32::from_be_bytes(r.array()?)),
            T::S64 => Self::S64(i64::from_be_bytes(r.array()?)),
            T::U8Array => Self::U8Array(r.take(usize::from(pb))?.to_vec()),
            T::U16Array => Self::U16Array(array(r, pb, u16::from_be_bytes)?),
            T::U32Array => Self::U32Array(array(r, pb, u32::from_be_bytes)?),
            T::F32Array => Self::F32Array(array(r, pb, f32::from_be_bytes)?),
            T::F64Array => Self::F64Array(array(r, pb, f64::from_be_bytes)?),
            T::S8Array => Self::S8Array(array(r, pb, i8::from_be_bytes)?),
            T::S16Array => Self::S16Array(array(r, pb, i16::from_be_bytes)?),
            T::S32Array => Self::S32Array(array(r, pb, i32::from_be_bytes)?),
            T::String => Self::String(text::decode_fixed(r.take(usize::from(pb))?)),
            T::DateTime => Self::Empty,
        })
    }

    pub fn decode(bytes: &[u8], typ: TypeCode, pb: u16) -> Result<Self, DecodeError> {
        let mut r = Reader::new(NAME, bytes);
        let value = Self::read(&mut r, typ, pb)?;
        if r.remaining() != 0 {
            return Err(DecodeError::Length {
                structure: NAME,
                len: bytes.len(),
            });
        }
        Ok(value)
    }

    pub fn write(&self, out: &mut Vec<u8>, typ: TypeCode, pb: u16) -> Result<(), DecodeError> {
        use TypeCode as T;
        let n = usize::from(pb);
        let mismatch = DecodeError::Invalid {
            structure: NAME,
            reason: "value does not fit the field",
        };
        match (self, typ) {
            (Self::U8(v), T::U8) => out.push(*v),
            (Self::U16(v), T::U16) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::U32(v), T::U32) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::U64(v), T::U64) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::F32(v), T::F32) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::F64(v), T::F64) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::S8(v), T::S8) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::S16(v), T::S16) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::S32(v), T::S32) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::S64(v), T::S64) => out.extend_from_slice(&v.to_be_bytes()),
            (Self::U8Array(v), T::U8Array) if v.len() == n => out.extend_from_slice(v),
            (Self::U16Array(v), T::U16Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::U32Array(v), T::U32Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::F32Array(v), T::F32Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::F64Array(v), T::F64Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::S8Array(v), T::S8Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::S16Array(v), T::S16Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::S32Array(v), T::S32Array) if v.len() == n => v
                .iter()
                .for_each(|x| out.extend_from_slice(&x.to_be_bytes())),
            (Self::String(s), T::String) => out.extend_from_slice(&text::encode_fixed(s, n)),
            (Self::Empty, T::DateTime) => {}
            _ => return Err(mismatch),
        }
        Ok(())
    }

    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        Some(match *self {
            Self::U8(v) => v.into(),
            Self::U16(v) => v.into(),
            Self::U32(v) => v.into(),
            Self::U64(v) => u64_to_f64(v),
            Self::F32(v) => v.into(),
            Self::F64(v) => v,
            Self::S8(v) => v.into(),
            Self::S16(v) => v.into(),
            Self::S32(v) => v.into(),
            Self::S64(v) => i64_to_f64(v),
            _ => return None,
        })
    }

    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        Some(match *self {
            Self::U8(v) => v.into(),
            Self::U16(v) => v.into(),
            Self::U32(v) => v.into(),
            Self::U64(v) => v,
            _ => return None,
        })
    }
}

#[allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "rounding to the nearest f64 is the intended conversion"
)]
const fn u64_to_f64(v: u64) -> f64 {
    v as f64
}

#[allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "rounding to the nearest f64 is the intended conversion"
)]
const fn i64_to_f64(v: i64) -> f64 {
    v as f64
}
