use kmb::decode::{encode_kmb_string, kmb_string};
use kmb::{DecodeError, Family, Identify};

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn vector_11_1() {
    let id = Identify::decode(&hex("30 39 94 00 00 30 18 D1 00 02 00 A0 01 30 00 00
         00 00 00 00 00 00 00 00 02 00"))
    .unwrap();
    assert_eq!(id.device_no, 12345);
    assert_eq!(id.device_type, 0x9400);
    assert_eq!(id.props_type, 48);
    assert_eq!(id.software_version, 0x18D1);
    assert_eq!(id.build(), 6353);
    assert_eq!(id.hardware_version, 2);
    assert_eq!(id.software_modules, 0x00A0);
    assert!(id.is_universal());
    assert_eq!(id.device_addr, 1);
    assert_eq!(id.bootloader_version, 48);
    assert_eq!(id.sub_device_type, [0, 0, 0, 0, 0, 0x0200]);
    assert_eq!(id.name, None);
    assert_eq!(id.archive_def, None);
    assert_eq!(id.family(), Some(Family::SmpG3));
}

const HEADER: &str = "94 00 00 30 18 D1 00 02 00 A0 01 30";

#[test]
fn accepted_lengths() {
    for len in 0..=100 {
        let mut payload = hex("30 39");
        payload.extend(hex(HEADER));
        payload.resize(len.max(14), 0);
        payload.truncate(len);
        let ok = Identify::decode(&payload).is_ok();
        assert_eq!(
            ok,
            [14, 15, 16, 17, 26, 28, 48, 56, 66, 88].contains(&len),
            "length {len}"
        );
    }
}

#[test]
fn device_no_width() {
    let mut p17 = hex("00 01 E2 40");
    p17.extend(hex(HEADER));
    p17.push(0xAA);
    let id = Identify::decode(&p17).unwrap();
    assert_eq!(id.device_no, 123_456);
    assert_eq!(id.device_type, 0x9400);

    let mut p16 = hex("30 39");
    p16.extend(hex(HEADER));
    p16.extend(hex("00 25"));
    assert_eq!(
        Identify::decode(&p16).unwrap().sub_device_type,
        [0x25, 0, 0, 0, 0, 0]
    );
}

#[test]
fn names_88() {
    let mut p = hex("00 00 30 39");
    p.extend(hex(HEADER));
    p.extend(encode_kmb_string("S01", 32));
    p.extend(encode_kmb_string("ARCH", 40));
    let id = Identify::decode(&p).unwrap();
    assert_eq!(id.name.as_deref(), Some("S01"));
    assert_eq!(id.archive_def.as_deref(), Some("ARCH"));
}

#[test]
fn bootloader_ff() {
    let mut p = hex("30 39 94 00 00 30 18 D1 00 02 00 A0 01 FF");
    assert_eq!(Identify::decode(&p).unwrap().bootloader_version, 0);
    p[13] = 0x30;
    assert_eq!(Identify::decode(&p).unwrap().bootloader_version, 0x30);
}

#[test]
fn family_decode() {
    let mk = |dt: u16, props: u16| {
        let mut p = hex("30 39");
        p.extend(dt.to_be_bytes());
        p.extend(props.to_be_bytes());
        p.extend(hex("18 D1 00 02 00 00 01 30"));
        Identify::decode(&p)
    };
    assert_eq!(mk(0, 0).unwrap().family(), Some(Family::SmpClassic));
    assert_eq!(mk(0x8100, 48).unwrap().family(), Some(Family::SmpOlder));
    assert_eq!(mk(0xB100, 48).unwrap().family(), Some(Family::SmpOlder));
    assert_eq!(mk(0x1000, 48).unwrap().family(), Some(Family::ShortFrame));
    assert_eq!(mk(0x5000, 7).unwrap().family(), Some(Family::OtherProps(7)));
    assert!(matches!(mk(0x5000, 48), Err(DecodeError::Invalid { .. })));
    assert!(!mk(0x9400, 48).unwrap().is_universal());
}

#[cfg(test)]
fn with(sv: u16, modules: u16, sub: [u16; 6]) -> Identify {
    let mut p = hex("30 39 94 00 00 30");
    p.extend(sv.to_be_bytes());
    p.extend(hex("00 02"));
    p.extend(modules.to_be_bytes());
    p.extend(hex("01 30"));
    for s in sub {
        p.extend(s.to_be_bytes());
    }
    Identify::decode(&p).unwrap()
}

#[test]
fn version_strings() {
    let id = with(0x18D1, 0, [0; 6]);
    assert_eq!(id.firmware_version(), "0.9.0.6353");
    assert_eq!(id.bootloader(), "4.8");
    assert_eq!(with(0x58D1, 0, [0; 6]).firmware_version(), "1.0.0.6353");
}

#[test]
fn adjust_time_threshold() {
    let mk = |sv: u16| {
        let mut p = hex("30 39 40 00 00 30");
        p.extend(sv.to_be_bytes());
        p.extend(hex("00 02 00 00 01 30"));
        Identify::decode(&p).unwrap()
    };
    assert!(!mk(19165).takes_absolute_adjust_time());
    assert!(mk(19166).takes_absolute_adjust_time());
}

#[test]
fn kmb_strings() {
    assert_eq!(kmb_string(b"abc\0def"), "abc");
    assert_eq!(kmb_string(b"abcd"), "abcd");
    assert_eq!(encode_kmb_string("", 4), [0, 0, 0, 0]);
    assert_eq!(encode_kmb_string("abcdef", 4), b"abc\0");
    assert_eq!(encode_kmb_string("abé", 4), b"ab\0\0");
}

#[test]
fn rtc_vector_11_10() {
    let rtc = kmb::Rtc::decode(&hex("00 01 00 00 00 C4 82 39 8E 00")).unwrap();
    assert_eq!(rtc.time, kmb::KmbTime(843_998_400_000));
    assert_eq!(rtc.extra, None);
}

#[test]
fn rtc_tag_and_extra() {
    assert!(kmb::Rtc::decode(&hex("00 02 00 00 00 C4 82 39 8E 00")).is_err());
    assert!(kmb::Rtc::decode(&hex("00 01 00 00")).is_err());
    let rtc = kmb::Rtc::decode(&hex(
        "00 01 00 00 00 C4 82 39 8E 00 00 00 00 00 00 00 01 02",
    ))
    .unwrap();
    assert_eq!(rtc.extra, Some(0x0102));
}
