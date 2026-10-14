use crate::frame::{Frame, FrameError};
use aes::Aes128;
use aes::cipher::array::Array;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::typenum::{U16, U32};
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

pub const ENVELOPE_COMMAND: u8 = 111;
pub const VERSION: u8 = 1;
pub const RANDOM_LEN: usize = 32;
pub const UID_LEN: usize = 12;
pub const PBKDF2_ROUNDS: u32 = 100_000;

const MAC_LEN: usize = 32;
const BLOCK_LEN: usize = 16;
const MIN_PAYLOAD_LEN: usize = 1 + RANDOM_LEN + BLOCK_LEN + MAC_LEN;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type HmacSha256 = Hmac<Sha256>;
type MessageKey = Array<u8, U32>;

#[derive(Clone, PartialEq, Eq)]
pub struct Psk(pub [u8; 32]);

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPsk;

impl fmt::Display for InvalidPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSK is not Base64 of exactly 32 bytes")
    }
}

impl std::error::Error for InvalidPsk {}

impl Psk {
    pub fn from_base64(text: &str) -> Result<Self, InvalidPsk> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| InvalidPsk)?;
        bytes.try_into().map(Self).map_err(|_| InvalidPsk)
    }

    #[must_use]
    pub fn from_password(password: &str, salt: &str) -> Self {
        Self(pbkdf2::pbkdf2_hmac_array::<sha1::Sha1, 32>(
            password.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
        ))
    }

    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

#[must_use]
pub fn uid_string(uid: &[u8; UID_LEN]) -> String {
    let (pairs, _) = uid.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| format!("{hi:02X}{lo:02X}"))
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub version: u8,
    pub uid: [u8; UID_LEN],
}

impl Handshake {
    pub fn parse(data: &[u8]) -> Result<Self, EnvelopeError> {
        let Some((&version, rest)) = data.split_first() else {
            return Err(EnvelopeError::HandshakeTooShort(0));
        };
        let (&uid, _) = rest
            .split_first_chunk::<UID_LEN>()
            .ok_or(EnvelopeError::HandshakeTooShort(data.len()))?;
        Ok(Self { version, uid })
    }

    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.version == VERSION
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    HandshakeTooShort(usize),
    NotEnvelope(u8),
    Version(u8),
    BadLength(usize),
    BadMac,
    BadPadding,
    Inner(FrameError),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeTooShort(n) => write!(f, "handshake data of {n} bytes, need 13"),
            Self::NotEnvelope(c) => write!(f, "command {c} is not the envelope 111"),
            Self::Version(v) => write!(f, "envelope version {v} is not supported"),
            Self::BadLength(n) => write!(f, "envelope payload of {n} bytes is malformed"),
            Self::BadMac => f.write_str("envelope MAC does not match"),
            Self::BadPadding => f.write_str("envelope padding does not check"),
            Self::Inner(e) => write!(f, "inner frame: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

fn derive_key(psk: &Psk, random: &[u8; RANDOM_LEN]) -> MessageKey {
    let mut sha = Sha256::new();
    sha.update(psk.0);
    sha.update(random);
    sha.finalize()
}

fn mac(key: &MessageKey) -> HmacSha256 {
    <HmacSha256 as KeyInit>::new(&key.concat(Array::<u8, U32>::default()))
}

fn cbc_key_iv<'a>(
    key: &'a MessageKey,
    random: &'a [u8; RANDOM_LEN],
) -> (&'a Array<u8, U16>, &'a Array<u8, U16>) {
    let random: &Array<u8, U32> = random.into();
    (key.split_ref::<U16>().0, random.split_ref::<U16>().0)
}

pub fn wrap(psk: &Psk, random: &[u8; RANDOM_LEN], inner: &Frame) -> Result<Frame, FrameError> {
    let plain = inner.encode()?;
    let key = derive_key(psk, random);
    let (aes_key, iv) = cbc_key_iv(&key, random);
    let cipher = Aes128CbcEnc::new(aes_key, iv).encrypt_padded_vec::<Pkcs7>(&plain);

    let mut payload = Vec::with_capacity(cipher.len().saturating_add(1 + RANDOM_LEN + MAC_LEN));
    payload.push(VERSION);
    payload.extend_from_slice(random);
    payload.extend_from_slice(&cipher);
    let mut hmac = mac(&key);
    hmac.update(&payload);
    payload.extend_from_slice(&hmac.finalize().into_bytes());
    Ok(Frame::new(inner.address, ENVELOPE_COMMAND, payload))
}

pub fn unwrap(psk: &Psk, outer: &Frame) -> Result<Frame, EnvelopeError> {
    if outer.command != ENVELOPE_COMMAND {
        return Err(EnvelopeError::NotEnvelope(outer.command));
    }
    let payload = outer.payload.as_slice();
    let bad_length = || EnvelopeError::BadLength(payload.len());
    let (signed, tag) = payload
        .split_last_chunk::<MAC_LEN>()
        .ok_or_else(bad_length)?;
    let (&version, rest) = signed.split_first().ok_or_else(bad_length)?;
    let (random, cipher) = rest
        .split_first_chunk::<RANDOM_LEN>()
        .ok_or_else(bad_length)?;
    if payload.len() < MIN_PAYLOAD_LEN || !cipher.len().is_multiple_of(BLOCK_LEN) {
        return Err(bad_length());
    }
    if version != VERSION {
        return Err(EnvelopeError::Version(version));
    }
    let key = derive_key(psk, random);

    let mut hmac = mac(&key);
    hmac.update(signed);
    hmac.verify_slice(tag).map_err(|_| EnvelopeError::BadMac)?;

    let (aes_key, iv) = cbc_key_iv(&key, random);
    let plain = Aes128CbcDec::new(aes_key, iv)
        .decrypt_padded_vec::<Pkcs7>(cipher)
        .map_err(|_| EnvelopeError::BadPadding)?;
    Frame::decode(&plain).map_err(EnvelopeError::Inner)
}
