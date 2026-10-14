use crate::decode::{DecodeError, Reader};

const NAME: &str = "identify";

pub const MODULE_UNI: u16 = 0x0080;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identify {
    pub device_no: u32,
    pub device_type: u16,
    pub props_type: u16,
    pub software_version: u16,
    pub hardware_version: u16,
    pub software_modules: u16,
    pub device_addr: u8,
    pub bootloader_version: u8,
    pub sub_device_type: [u16; 6],
    pub name: Option<String>,
    pub archive_def: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    SmpG3,
    SmpOlder,
    SmpClassic,
    ShortFrame,
    OtherProps(u16),
}

impl Identify {
    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let len = payload.len();
        if ![14, 15, 16, 17, 26, 28, 48, 56, 66, 88].contains(&len) {
            return Err(DecodeError::Length {
                structure: NAME,
                len,
            });
        }
        let mut r = Reader::new(NAME, payload);
        let device_no = match len {
            17 | 28 | 48 | 88 => r.u32()?,
            _ => u32::from(r.u16()?),
        };
        let device_type = r.u16()?;
        let props_type = r.u16()?;
        let software_version = r.u16()?;
        let hardware_version = r.u16()?;
        let software_modules = r.u16()?;
        let device_addr = r.u8()?;
        let bootloader_version = match r.u8()? {
            0xFF => 0,
            v => v,
        };
        let mut sub_device_type = [0; 6];
        let mut name = None;
        match len {
            16 | 56 => {
                let [first, ..] = &mut sub_device_type;
                *first = r.u16()?;
            }
            26 | 28 | 66 => {
                for sub in &mut sub_device_type {
                    *sub = r.u16()?;
                }
            }
            48 | 88 => name = Some(r.string(32)?),
            _ => {}
        }
        let archive_def = match len {
            56 | 66 | 88 => Some(r.string(40)?),
            _ => None,
        };
        let identify = Self {
            device_no,
            device_type,
            props_type,
            software_version,
            hardware_version,
            software_modules,
            device_addr,
            bootloader_version,
            sub_device_type,
            name,
            archive_def,
        };
        if identify.family().is_none() {
            return Err(DecodeError::Invalid {
                structure: NAME,
                reason: "unknown device type",
            });
        }
        Ok(identify)
    }

    #[must_use]
    pub const fn is_universal(&self) -> bool {
        self.software_modules & MODULE_UNI != 0
    }

    #[must_use]
    pub const fn build(&self) -> u16 {
        self.software_version & 0x3FFF
    }

    #[must_use]
    pub fn takes_absolute_adjust_time(&self) -> bool {
        u32::from(self.software_version) >= crate::command::ADJUST_TIME_ABSOLUTE_FROM
    }

    #[must_use]
    pub const fn family(&self) -> Option<Family> {
        let props = if self.props_type == 0 {
            48
        } else {
            self.props_type
        };
        if props != 48 {
            return Some(Family::OtherProps(props));
        }
        let dt = if self.device_type == 0 {
            0x4000
        } else {
            self.device_type
        };
        match (dt & 0xF000, dt & 0xFF00) {
            (0x9000, _) => Some(Family::SmpG3),
            (0x7000 | 0x8000, _) | (_, 0xB100) => Some(Family::SmpOlder),
            (0x3000 | 0x4000 | 0x6000, _) => Some(Family::SmpClassic),
            (0x0000 | 0x1000 | 0xA000, _) => Some(Family::ShortFrame),
            _ => None,
        }
    }

    #[must_use]
    pub fn firmware_version(&self) -> String {
        let prefix = if self.software_version >> 14 == 0 {
            "0.9.0."
        } else {
            "1.0.0."
        };
        format!("{prefix}{}", self.build())
    }

    #[must_use]
    pub fn bootloader(&self) -> String {
        format!(
            "{}.{}",
            self.bootloader_version / 10,
            self.bootloader_version % 10
        )
    }
}
