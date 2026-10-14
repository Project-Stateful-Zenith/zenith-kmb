use crate::decode::{DecodeError, Reader};

const CP1252_HIGH: [char; 32] = [
    '\u{20AC}', '\u{81}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{8D}', '\u{017D}', '\u{8F}',
    '\u{90}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{9D}', '\u{017E}', '\u{0178}',
];

#[must_use]
pub fn decode_cp1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9F => CP1252_HIGH
                .get(usize::from(b & 0x1F))
                .copied()
                .unwrap_or_else(|| char::from(b)),
            _ => char::from(b),
        })
        .collect()
}

#[must_use]
pub fn encode_cp1252(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| match u8::try_from(c) {
            Ok(b @ (0..=0x7F | 0xA0..=0xFF)) => b,
            _ => CP1252_HIGH
                .iter()
                .position(|&h| h == c)
                .and_then(|i| u8::try_from(i).ok())
                .map_or(b'?', |i| 0x80 | i),
        })
        .collect()
}

pub const SHORT_MAX: usize = 30;
pub const ARCHIVE_NAME_MAX: usize = 32;

pub(crate) fn read_short(r: &mut Reader<'_>, max: usize) -> Result<String, DecodeError> {
    let mut bytes = Vec::new();
    while bytes.len() < max {
        match r.u8()? {
            0 => break,
            b => bytes.push(b),
        }
    }
    Ok(decode_cp1252(&bytes))
}

pub(crate) fn write_short(out: &mut Vec<u8>, text: &str, max: usize) {
    let mut bytes = encode_cp1252(text);
    bytes.truncate(max);
    let full = bytes.len() == max;
    out.extend_from_slice(&bytes);
    if !full {
        out.push(0);
    }
}

#[must_use]
pub fn decode_fixed(field: &[u8]) -> String {
    let text = field.split(|&b| b == 0).next().unwrap_or(field);
    decode_cp1252(text)
}

#[must_use]
pub fn encode_fixed(text: &str, n: usize) -> Vec<u8> {
    let mut bytes = encode_cp1252(text);
    bytes.resize(n, 0);
    bytes
}
