use kmb::command::{self, AdjustResult, cmd, info, reset};
use kmb::{Frame, KmbTime};

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn empty_gets() {
    assert_eq!(
        command::identify(1).encode().unwrap(),
        hex("01 00 00 01 18 C0")
    );
    assert_eq!(
        command::get(1, cmd::GET_STATUS).encode().unwrap(),
        hex("01 00 00 14 D7 01")
    );
}

#[test]
fn e6_set_rtc() {
    let frame = command::set_rtc(1, 0x78CD_6D02, KmbTime(842_961_600_000));
    assert_eq!(
        frame.encode().unwrap(),
        hex("01 00 12 10 78 CD 6D 02 00 00 00 00 00 01 00 00 00 C4 44 6D 3E 00 D3 AF")
    );
}

#[test]
fn reset_payload() {
    let frame = command::reset(9, 0x0102_0304, reset::ADMIN);
    assert_eq!(
        frame,
        Frame::new(9, 0, hex("01 02 03 04 00 00 00 00 63 A2 79 3B"))
    );
}

#[test]
fn get_rtc_payload() {
    assert_eq!(command::get_rtc(1), Frame::new(1, 17, [0x00, 0x01]));
}

#[test]
fn adjust_time_forms() {
    assert_eq!(
        command::adjust_time_legacy(1, 3599),
        Frame::new(1, 18, [0x0E, 0x0F, 0xFF])
    );
    assert_eq!(
        command::adjust_time_absolute(1, KmbTime(842_961_600_000)),
        Frame::new(1, 18, hex("00 00 00 C4 44 6D 3E 00 FF"))
    );
    let uni = command::adjust_time_universal(1, 0x78CD_6D02, KmbTime(842_961_600_000));
    assert_eq!(
        uni,
        Frame::new(
            1,
            18,
            hex("78 CD 6D 02 00 00 00 00 00 00 00 00 00 C4 44 6D 3E 00")
        )
    );
    assert_eq!(uni.payload.len(), 18);
}

#[test]
fn adjust_result() {
    assert_eq!(AdjustResult::from(0x00), AdjustResult::Full);
    assert_eq!(AdjustResult::from(0xC0), AdjustResult::Partial);
    assert_eq!(AdjustResult::from(0x90), AdjustResult::ShortRecordLength);
    assert_eq!(AdjustResult::from(0xA0), AdjustResult::BadSyncConfig);
    assert_eq!(AdjustResult::from(0x01), AdjustResult::Error(1));
}

#[test]
fn record_by_time_payload() {
    assert_eq!(
        command::record_by_time(1, 3, KmbTime(842_961_600_000)),
        Frame::new(1, 23, hex("03 00 00 00 C4 44 6D 3E 00"))
    );
}

#[test]
fn sub_constants() {
    assert_eq!(command::get_sub_constants(1, 5), Frame::new(1, 34, [5]));
    assert_eq!(
        command::set_sub_constants(1, 0x0A0B_0C0D, 5, &[0xEE, 0xFF]),
        Frame::new(1, 33, hex("0A 0B 0C 0D 00 00 00 00 05 EE FF"))
    );
}

#[test]
fn elmer() {
    assert_eq!(
        command::set_shape_b(1, cmd::SET_ELMER_TARIFF, 0x0A0B_0C0D, &[0x77]),
        Frame::new(1, 51, hex("00 00 00 00 0A 0B 0C 0D 77"))
    );
    assert_eq!(command::get_elmer(1), Frame::new(1, 52, [0]));
}

#[test]
fn profiles() {
    assert_eq!(
        command::set_s_profile_day(1, 17, 9),
        Frame::new(1, 55, hex("00 00 00 00 00 00 00 00 11 09"))
    );
    assert_eq!(
        command::clear_m_profile(1, 0x0102_0304),
        Frame::new(1, 56, hex("01 02 03 04 00 00 00 00"))
    );
}

#[test]
fn mask_info_mtu() {
    assert_eq!(
        command::act_data(1, command::ACT_DATA_ALL),
        Frame::new(1, 58, [0xFF; 4])
    );
    assert_eq!(command::info(1, info::ETH), Frame::new(1, 70, [0, 0, 0, 8]));
    assert_eq!(
        command::info(1, info::raw_archive(3)),
        Frame::new(1, 70, [0, 0, 0x03, 0xEB])
    );
    let probe = command::mtu_probe(1, 10);
    assert_eq!(probe.payload, [1; 10]);
    assert_eq!(probe.command, 146);
}

#[test]
fn set_notebook() {
    let notebook = [0x41; 64];
    let frame = command::set(1, cmd::SET_NOTEBOOK, 0x0102_0304, &notebook);
    assert_eq!(frame.payload.len(), 72);
    assert_eq!(frame.payload[..8], hex("01 02 03 04 00 00 00 00"));
    assert_eq!(frame.payload[8..], notebook);
}
