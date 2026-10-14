use crate::frame::Frame;
use crate::pin;
use crate::time::KmbTime;

pub mod cmd {
    pub const RESET: u8 = 0;
    pub const IDENTIFY: u8 = 1;
    pub const SET_RTC: u8 = 16;
    pub const GET_RTC: u8 = 17;
    pub const ADJUST_TIME: u8 = 18;
    pub const GET_STATUS: u8 = 20;
    pub const GET_RECORD: u8 = 22;
    pub const RECORD_BY_TIME: u8 = 23;
    pub const SET_CONSTANTS: u8 = 26;
    pub const GET_CONSTANTS: u8 = 27;
    pub const GET_NOTEBOOK: u8 = 31;
    pub const SET_NOTEBOOK: u8 = 32;
    pub const SET_SUB_CONSTANTS: u8 = 33;
    pub const GET_SUB_CONSTANTS: u8 = 34;
    pub const SET_ARC_CONFIG: u8 = 35;
    pub const GET_INSTALL_CONFIG: u8 = 38;
    pub const SET_INSTALL_CONFIG: u8 = 39;
    pub const GET_MODEM_INIT: u8 = 40;
    pub const SET_MODEM_INIT: u8 = 41;
    pub const GET_OUTPUT_CONFIG: u8 = 48;
    pub const SET_OUTPUT_CONFIG: u8 = 49;
    pub const GET_ELMER_TARIFF: u8 = 50;
    pub const SET_ELMER_TARIFF: u8 = 51;
    pub const GET_ELMER: u8 = 52;
    pub const GET_PROFILE_STATUS: u8 = 54;
    pub const SET_S_PROFILE_TIME: u8 = 55;
    pub const CLEAR_M_PROFILE: u8 = 56;
    pub const GET_ALL_ACT_DATA: u8 = 58;
    pub const INFO: u8 = 70;
    pub const GET_DISPLAY: u8 = 71;
    pub const SET_DISPLAY: u8 = 72;
    pub const GET_CONFIG: u8 = 78;
    pub const SET_CONFIG: u8 = 79;
    pub const GET_PQ_SETTINGS: u8 = 82;
    pub const SET_PQ_SETTINGS: u8 = 83;
    pub const SET_MODULES: u8 = 98;
    pub const GET_ADDITIONAL_CONFIG: u8 = 99;
    pub const SET_ADDITIONAL_CONFIG: u8 = 100;
    pub const ENCRYPTED: u8 = 111;
    pub const BROADCAST: u8 = 145;
    pub const MTU_PROBE: u8 = 146;
}

pub mod reset {
    pub const MAIN: u32 = 0x0000_0000;
    pub const S_PROFILE: u32 = 0x0000_0001;
    pub const M_PROFILE: u32 = 0x0000_0002;
    pub const LOG: u32 = 0x0000_0003;
    pub const PQ_MAIN: u32 = 0x0000_0004;
    pub const PQ_EVENTS: u32 = 0x0000_0005;
    pub const ELMER: u32 = 0x0000_0006;
    pub const PQ_OSCILLOGRAM: u32 = 0x0000_0008;
    pub const PQ_EVENT_TREND_ARCHIVE: u32 = 0x0000_0009;
    pub const HDO_ARCHIVE: u32 = 0x0000_000A;
    pub const VLNY_ARCHIVE: u32 = 0x0000_000B;
    pub const MM_ARCHIVE: u32 = 0x0000_000C;
    pub const TEN_MINS: u32 = 0x0000_000D;
    pub const PQ_TABLE: u32 = 0x0000_000E;
    pub const HISTOGRAM: u32 = 0x0000_000F;
    pub const ACT_ELMER: u32 = 0x0000_0100;
    pub const PAVG_MAX_CMLM: u32 = 0x0000_0200;
    pub const PAVG_MAX_TOT: u32 = 0x0000_0300;
    pub const UIAVG_MAX: u32 = 0x0000_0301;
    pub const PQAVG_MAX: u32 = 0x0000_0302;
    pub const RCM_MAX: u32 = 0x0000_0303;
    pub const GRAPHS: u32 = 0x0000_0400;
    pub const MAX_DB1: u32 = 0x0000_0500;
    pub const MAX_DB2: u32 = 0x0000_0600;
    pub const DEVICE: u32 = 0x7365_72FF;
    pub const ADMIN: u32 = 0x63A2_793B;
    pub const SNTP_SYNC: u32 = 0x2C22_649B;
    pub const SUSPEND_RECORD: u32 = 0x256A_A120;
    pub const RESUME_RECORD: u32 = 0x256A_A121;
    pub const COMM_STARTGO: u32 = 0xAAAA_AAA1;
    pub const COMM_STARTPQOSC: u32 = 0xAAAA_AAA2;
    pub const COMM_STARTPQTREND: u32 = 0xAAAA_AAA3;
}

pub mod info {
    pub const BLOCKS: u32 = 1;
    pub const TIMES: u32 = 2;
    pub const TOU: u32 = 3;
    pub const TIMES_MAX: u32 = 4;
    pub const ECC_STATE: u32 = 5;
    pub const COMMUNICATION: u32 = 6;
    pub const WDG: u32 = 7;
    pub const ETH: u32 = 8;

    #[must_use]
    pub const fn raw_archive(n: u32) -> u32 {
        1000u32.saturating_add(n)
    }
}

#[must_use]
pub fn get(address: u8, command: u8) -> Frame {
    Frame::new(address, command, [])
}

#[must_use]
pub fn identify(address: u8) -> Frame {
    get(address, cmd::IDENTIFY)
}

#[must_use]
pub fn set(address: u8, command: u8, pin: u32, data: &[u8]) -> Frame {
    let mut payload = pin::block_a(pin).to_vec();
    payload.extend_from_slice(data);
    Frame::new(address, command, payload)
}

#[must_use]
pub fn set_shape_b(address: u8, command: u8, pin: u32, data: &[u8]) -> Frame {
    let mut payload = pin::block_b(pin).to_vec();
    payload.extend_from_slice(data);
    Frame::new(address, command, payload)
}

#[must_use]
pub fn reset(address: u8, pin: u32, code: u32) -> Frame {
    set(address, cmd::RESET, pin, &code.to_be_bytes())
}

#[must_use]
pub fn get_rtc(address: u8) -> Frame {
    Frame::new(address, cmd::GET_RTC, 1u16.to_be_bytes())
}

#[must_use]
pub fn set_rtc(address: u8, pin: u32, time: KmbTime) -> Frame {
    let mut data = 1u16.to_be_bytes().to_vec();
    data.extend_from_slice(&time.to_be_bytes());
    set(address, cmd::SET_RTC, pin, &data)
}

#[must_use]
pub fn adjust_time_legacy(address: u8, seconds_into_hour: u16) -> Frame {
    let [hi, lo] = seconds_into_hour.to_be_bytes();
    Frame::new(address, cmd::ADJUST_TIME, [hi, lo, 0xFF])
}

#[must_use]
pub fn adjust_time_absolute(address: u8, time: KmbTime) -> Frame {
    let mut payload = time.to_be_bytes().to_vec();
    payload.push(0xFF);
    Frame::new(address, cmd::ADJUST_TIME, payload)
}

#[must_use]
pub fn adjust_time_universal(address: u8, pin: u32, time: KmbTime) -> Frame {
    let mut data = 0u16.to_be_bytes().to_vec();
    data.extend_from_slice(&time.to_be_bytes());
    set(address, cmd::ADJUST_TIME, pin, &data)
}

pub const ADJUST_TIME_ABSOLUTE_FROM: u32 = 19166;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdjustResult {
    Full,
    Partial,
    ShortRecordLength,
    BadSyncConfig,
    Error(u8),
}

impl From<u8> for AdjustResult {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Self::Full,
            0xC0 => Self::Partial,
            0x90 => Self::ShortRecordLength,
            0xA0 => Self::BadSyncConfig,
            other => Self::Error(other),
        }
    }
}

#[must_use]
pub fn record_by_time(address: u8, archive: u8, time: KmbTime) -> Frame {
    let mut payload = vec![archive];
    payload.extend_from_slice(&time.to_be_bytes());
    Frame::new(address, cmd::RECORD_BY_TIME, payload)
}

#[must_use]
pub fn get_sub_constants(address: u8, id: u8) -> Frame {
    Frame::new(address, cmd::GET_SUB_CONSTANTS, [id])
}

#[must_use]
pub fn set_sub_constants(address: u8, pin: u32, id: u8, constants: &[u8]) -> Frame {
    let mut data = vec![id];
    data.extend_from_slice(constants);
    set(address, cmd::SET_SUB_CONSTANTS, pin, &data)
}

#[must_use]
pub fn get_elmer(address: u8) -> Frame {
    Frame::new(address, cmd::GET_ELMER, [0])
}

#[must_use]
pub fn set_s_profile_day(address: u8, day: u8, month: u8) -> Frame {
    let mut payload = vec![0; 8];
    payload.extend_from_slice(&[day, month]);
    Frame::new(address, cmd::SET_S_PROFILE_TIME, payload)
}

#[must_use]
pub fn clear_m_profile(address: u8, pin: u32) -> Frame {
    set(address, cmd::CLEAR_M_PROFILE, pin, &[])
}

#[must_use]
pub fn act_data(address: u8, mask: u32) -> Frame {
    Frame::new(address, cmd::GET_ALL_ACT_DATA, mask.to_be_bytes())
}

pub const ACT_DATA_ALL: u32 = 0xFFFF_FFFF;

#[must_use]
pub fn info(address: u8, block: u32) -> Frame {
    Frame::new(address, cmd::INFO, block.to_be_bytes())
}

#[must_use]
pub fn mtu_probe(address: u8, len: u16) -> Frame {
    Frame::new(address, cmd::MTU_PROBE, vec![0x01; usize::from(len)])
}

pub const MTU_PROBE_SIZES: [u16; 4] = [10, 6800, 1300, 500];
