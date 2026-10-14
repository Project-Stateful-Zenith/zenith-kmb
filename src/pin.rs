use md5::{Digest, Md5};

#[must_use]
pub fn user_hash(user: &str, password: &str) -> u32 {
    let mut md5 = Md5::new();
    md5.update(user.as_bytes());
    md5.update(password.as_bytes());
    let digest: [u8; 16] = md5.finalize().into();
    let [b0, b1, b2, b3, ..] = digest;
    u32::from_le_bytes([b0, b1, b2, b3])
}

#[must_use]
pub const fn wire_pin(user_hash: u32, device_no: u32) -> u32 {
    user_hash.wrapping_add(device_no)
}

#[must_use]
pub const fn block_a(pin: u32) -> [u8; 8] {
    let [p0, p1, p2, p3] = pin.to_be_bytes();
    [p0, p1, p2, p3, 0, 0, 0, 0]
}

#[must_use]
pub fn block_b(pin: u32) -> [u8; 8] {
    u64::from(pin).to_be_bytes()
}
