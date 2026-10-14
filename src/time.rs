const EPOCH_2000_UNIX_MS: i64 = 946_684_800_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KmbTime(pub u64);

impl KmbTime {
    pub const INVALID: Self = Self(u64::MAX);

    #[must_use]
    pub const fn from_unix_ms(unix_ms: i64) -> Self {
        match unix_ms.checked_sub(EPOCH_2000_UNIX_MS) {
            Some(ms) if ms >= 0 => Self(ms.cast_unsigned()),
            _ => Self::INVALID,
        }
    }

    #[must_use]
    pub fn to_unix_ms(self) -> Option<i64> {
        if self.is_invalid() {
            return None;
        }
        i64::try_from(self.0).ok()?.checked_add(EPOCH_2000_UNIX_MS)
    }

    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0 == Self::INVALID.0
    }

    #[must_use]
    pub const fn add_ms(self, ms: u64) -> Self {
        if self.is_invalid() {
            return self;
        }
        Self(self.0.saturating_add(ms))
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}
