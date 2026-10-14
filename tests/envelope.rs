use kmb::envelope::{self, uid_string};
use kmb::{EnvelopeError, Frame, Handshake, Psk, Reply, pin};

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(test)]
fn seq<const N: usize>(start: u8) -> [u8; N] {
    let mut values = start..=u8::MAX;
    std::array::from_fn(|_| values.next().unwrap())
}

#[test]
fn e6_pin() {
    let h = pin::user_hash("admin", "1234");
    assert_eq!(h, 0x78CD_3CC9);
    assert_eq!(pin::wire_pin(h, 12345), 0x78CD_6D02);
    assert_eq!(
        pin::block_a(0x78CD_6D02),
        [0x78, 0xCD, 0x6D, 0x02, 0, 0, 0, 0]
    );
}

#[test]
fn pin_shape_b() {
    assert_eq!(
        pin::block_b(0x78CD_6D02),
        [0, 0, 0, 0, 0x78, 0xCD, 0x6D, 0x02]
    );
}

const E9: &str = "01 00 51 6F 01 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32
    33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F A6 AC 72 5A 95 8E 26 91 3C 32 B0
    F5 38 BC C9 DA 70 77 CF DD EA C0 29 47 EB B7 10 99 1F D5 2E 2B C7 10 E0
    37 7E E6 26 13 D4 92 94 B6 09 E7 04 9C 51 17";

#[test]
fn e9_wrap() {
    let psk = Psk(seq(0x00));
    let outer = envelope::wrap(&psk, &seq(0x20), &Frame::new(1, 1, [])).unwrap();
    assert_eq!(outer.encode().unwrap(), hex(E9));
}

#[test]
fn e9_unwrap() {
    let psk = Psk(seq(0x00));
    let outer = Frame::decode(&hex(E9)).unwrap();
    assert_eq!(
        envelope::unwrap(&psk, &outer).unwrap(),
        Frame::new(1, 1, [])
    );
}

#[test]
fn unwrap_refuses_tampering() {
    let psk = Psk(seq(0x00));
    let outer = Frame::decode(&hex(E9)).unwrap();

    let mut flipped = outer.clone();
    flipped.payload[40] ^= 1;
    assert_eq!(envelope::unwrap(&psk, &flipped), Err(EnvelopeError::BadMac));

    assert_eq!(
        envelope::unwrap(&Psk([0; 32]), &outer),
        Err(EnvelopeError::BadMac)
    );

    let mut version = outer.clone();
    version.payload[0] = 2;
    assert_eq!(
        envelope::unwrap(&psk, &version),
        Err(EnvelopeError::Version(2))
    );

    let mut short = outer;
    short.payload.truncate(80);
    assert_eq!(
        envelope::unwrap(&psk, &short),
        Err(EnvelopeError::BadLength(80))
    );

    assert_eq!(
        envelope::unwrap(&psk, &Frame::new(1, 1, [0])),
        Err(EnvelopeError::NotEnvelope(1))
    );
}

#[test]
fn ciphertext_length() {
    let psk = Psk(seq(0x00));
    for n in [0usize, 9, 10, 26, 100] {
        let inner = Frame::new(7, 58, vec![0xA5; n]);
        let outer = envelope::wrap(&psk, &seq(0x40), &inner).unwrap();
        let c = outer.payload.len() - 1 - 32 - 32;
        assert_eq!(c, ((n + 6) / 16 + 1) * 16);
        assert_eq!(envelope::unwrap(&psk, &outer).unwrap(), inner);
    }
}

#[test]
fn e10_handshake() {
    let frame = Frame::decode(&hex(
        "01 00 0E 81 09 01 00 01 02 03 04 05 06 07 08 09 0A 0B 02 2B",
    ))
    .unwrap();
    let Reply::Error { data, .. } = frame.reply().unwrap() else {
        panic!()
    };
    let hs = Handshake::parse(data).unwrap();
    assert_eq!(
        hs,
        Handshake {
            version: 1,
            uid: seq(0x00)
        }
    );
    assert!(hs.is_supported());
    assert_eq!(uid_string(&hs.uid), "0001-0203-0405-0607-0809-0A0B");
    assert_eq!(
        Handshake::parse(&data[..12]),
        Err(EnvelopeError::HandshakeTooShort(12))
    );
}

#[test]
fn psk_from_password() {
    let psk = Psk::from_password("password", "0001-0203-0405-0607-0809-0A0B");
    let expected = hex("0849e9a149961dc597fd86ba965efc6dbb1960523e989a340fea7a92af5c87cb");
    assert_eq!(psk.0.as_slice(), expected);
    assert_eq!(
        psk.to_base64(),
        "CEnpoUmWHcWX/Ya6ll78bbsZYFI+mJo0D+p6kq9ch8s="
    );
    assert_eq!(
        Psk::from_base64("CEnpoUmWHcWX/Ya6ll78bbsZYFI+mJo0D+p6kq9ch8s=").unwrap(),
        psk
    );
}

#[test]
fn psk_base64_length() {
    assert!(Psk::from_base64("AAAA").is_err());
    assert!(Psk::from_base64("not base64!").is_err());
}

#[test]
fn unwrap_refuses_every_bad_length() {
    let psk = Psk(seq(0x00));
    for len in (0..81).chain((82..=144).filter(|n| (n - 65) % 16 != 0)) {
        let mut payload = vec![0; len];
        if let Some(version) = payload.first_mut() {
            *version = 1;
        }
        assert_eq!(
            envelope::unwrap(&psk, &Frame::new(1, 111, payload)),
            Err(EnvelopeError::BadLength(len)),
            "payload of {len} bytes"
        );
    }
}
