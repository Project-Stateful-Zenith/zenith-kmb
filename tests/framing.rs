use kmb::{ErrorCode, Frame, FrameDecoder, FrameError, KmbTime, Reply, crc16};

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn crc_check_value() {
    assert_eq!(crc16(b"123456789"), 0x4B37);
}

#[test]
fn e1_identify() {
    let bytes = hex("01 00 00 01 18 C0");
    assert_eq!(crc16(&bytes[..4]), 0x18C0);
    assert_eq!(Frame::new(1, 1, []).encode().unwrap(), bytes);
    assert_eq!(Frame::decode(&bytes).unwrap(), Frame::new(1, 1, []));
}

#[test]
fn e2_status() {
    assert_eq!(
        Frame::new(1, 20, []).encode().unwrap(),
        hex("01 00 00 14 D7 01")
    );
}

#[test]
fn e3_archive() {
    let payload = hex("00 00 00 00 00 00 01 00");
    assert_eq!(
        Frame::new(1, 22, payload).encode().unwrap(),
        hex("01 00 08 16 00 00 00 00 00 00 01 00 DB FF")
    );
}

#[test]
fn e4_ack() {
    let frame = Frame::decode(&hex("01 00 01 10 00 C0 45")).unwrap();
    assert!(frame.is_ack());
    assert_eq!(frame.command, 16);
}

#[test]
fn e5_error_reply() {
    let frame = Frame::decode(&hex("01 00 01 F1 08 56 0C")).unwrap();
    assert!(!frame.is_ack());
    assert_eq!(
        frame.reply().unwrap(),
        Reply::Error {
            command: 113,
            code: ErrorCode::NoPermission,
            data: &[]
        }
    );
}

#[test]
fn e6_set_rtc_frame() {
    let mut payload = hex("78 CD 6D 02 00 00 00 00 00 01");
    payload.extend_from_slice(&KmbTime(842_961_600_000).to_be_bytes());
    assert_eq!(
        Frame::new(1, 16, payload).encode().unwrap(),
        hex("01 00 12 10 78 CD 6D 02 00 00 00 00 00 01 00 00 00 C4 44 6D 3E 00 D3 AF")
    );
}

#[test]
fn e6_time() {
    let t = KmbTime::from_unix_ms(1_789_646_400_000);
    assert_eq!(t, KmbTime(842_961_600_000));
    assert_eq!(
        t.to_be_bytes(),
        [0x00, 0x00, 0x00, 0xC4, 0x44, 0x6D, 0x3E, 0x00]
    );
    assert_eq!(t.to_unix_ms(), Some(1_789_646_400_000));
}

#[test]
fn time_before_2000_is_invalid() {
    assert_eq!(KmbTime::from_unix_ms(0), KmbTime::INVALID);
    assert_eq!(KmbTime::from_be_bytes([0xFF; 8]).to_unix_ms(), None);
    assert_eq!(KmbTime::from_unix_ms(946_684_800_000), KmbTime(0));
}

#[test]
fn e7_locate() {
    assert_eq!(
        Frame::new(250, 145, [1]).encode().unwrap(),
        hex("FA 00 01 91 01 84 01")
    );
}

#[test]
fn e10_encryption_required() {
    let frame = Frame::decode(&hex(
        "01 00 0E 81 09 01 00 01 02 03 04 05 06 07 08 09 0A 0B 02 2B",
    ))
    .unwrap();
    let Reply::Error {
        command,
        code,
        data,
    } = frame.reply().unwrap()
    else {
        panic!("not an error reply");
    };
    assert_eq!(command, 1);
    assert_eq!(code, ErrorCode::EncryptionRequired);
    assert_eq!(data, hex("01 00 01 02 03 04 05 06 07 08 09 0A 0B"));
}

#[test]
fn un_reply_is_no_data() {
    let frame = Frame::new(1, 31, *b"Un");
    assert_eq!(frame.reply().unwrap(), Reply::NoData);
    assert_eq!(
        Frame::new(1, 31, *b"Unx").reply().unwrap(),
        Reply::Data(b"Unx")
    );
}

#[test]
fn empty_reply_is_refused() {
    assert!(
        Frame::decode(&hex("01 00 00 01 18 C0"))
            .unwrap()
            .reply()
            .is_err()
    );
}

#[test]
fn bad_crc() {
    assert_eq!(
        Frame::decode(&hex("01 00 00 01 18 C1")),
        Err(FrameError::BadCrc {
            stored: 0x18C1,
            computed: 0x18C0
        })
    );
}

#[test]
fn wrong_lengths() {
    assert_eq!(
        Frame::decode(&hex("01 00 00 01 18")),
        Err(FrameError::TooShort(5))
    );
    assert_eq!(
        Frame::decode(&hex("01 00 01 01 18 C0")),
        Err(FrameError::LengthMismatch {
            declared: 1,
            actual: 6
        })
    );
    assert_eq!(
        Frame::new(1, 1, vec![0; 65536]).encode(),
        Err(FrameError::PayloadTooLong(65536))
    );
}

#[test]
fn decoder_splits_by_length() {
    let mut stream = hex("01 00 01 10 00 C0 45");
    stream.extend(hex("01 00 01 F1 08 56 0C"));
    let mut dec = FrameDecoder::new();
    for chunk in stream.chunks(3) {
        dec.push(chunk);
    }
    assert!(dec.next_frame().unwrap().unwrap().is_ack());
    assert_eq!(dec.next_frame().unwrap().unwrap().command, 0xF1);
    assert!(dec.next_frame().is_none());
    assert_eq!(dec.buffered(), 0);

    let mut dec = FrameDecoder::new();
    dec.push(&hex("01 00 01 10"));
    assert!(dec.next_frame().is_none());
    dec.push(&hex("00 C0"));
    assert!(dec.next_frame().is_none());
    dec.push(&hex("45"));
    assert!(dec.next_frame().unwrap().unwrap().is_ack());
}

#[test]
fn decoder_discards_on_error() {
    let mut dec = FrameDecoder::new();
    dec.push(&hex("01 00 00 01 18 C1 01 00 00 01 18 C0"));
    assert!(matches!(
        dec.next_frame(),
        Some(Err(FrameError::BadCrc { .. }))
    ));
    assert_eq!(dec.buffered(), 0);

    let mut dec = FrameDecoder::with_max_payload(14000 - 6);
    dec.push(&hex("01 FF FF 01"));
    assert_eq!(
        dec.next_frame(),
        Some(Err(FrameError::OverLimit {
            declared: 65535,
            limit: 13994
        }))
    );
    assert_eq!(dec.buffered(), 0);
}

#[test]
fn truncated_frames_are_refused() {
    let bytes = hex("01 00 01 10 00 C0 45");
    for end in 0..bytes.len() {
        assert!(Frame::decode(&bytes[..end]).is_err(), "first {end} bytes");
        let mut dec = FrameDecoder::new();
        dec.push(&bytes[..end]);
        assert!(dec.next_frame().is_none(), "first {end} bytes");
    }
}
