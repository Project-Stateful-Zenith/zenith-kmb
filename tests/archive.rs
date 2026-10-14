use kmb::archive::uni::{self, Layout, Reject};
use kmb::archive::{self, Cursor, Geometry, RecordAtTime, ReplyHeader, kind};
use kmb::uni::{ArchiveDescription, ArchiveField, ArchiveGroup, Value};
use kmb::{KmbTime, command};

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    let nibbles: Vec<u8> = digits
        .iter()
        .filter_map(|c| c.to_digit(16))
        .filter_map(|d| u8::try_from(d).ok())
        .collect();
    assert_eq!(nibbles.len(), digits.len(), "not hex: {s}");
    let (pairs, odd) = nibbles.as_chunks::<2>();
    assert!(odd.is_empty(), "odd number of hex digits: {s}");
    pairs.iter().map(|&[hi, lo]| (hi << 4) | lo).collect()
}

#[test]
fn requests_9_1() {
    assert_eq!(
        archive::probe(1, kind::LOG).encode().unwrap(),
        hex("01 0008 16 03 00000000 0000 00 5EBE")
    );
    assert_eq!(
        archive::request(1, kind::LOG, 0, 2, 1).encode().unwrap(),
        hex("01 0008 16 03 00000000 0002 00 3EBF")
    );
    assert_eq!(
        archive::request(1, kind::MAIN, 500, 187, 3)
            .encode()
            .unwrap(),
        hex("01 0008 16 00 000001F4 00BB 02 8A02")
    );
    assert_eq!(
        archive::request_part(1, kind::MAIN, 42, 0, 1400)
            .encode()
            .unwrap(),
        hex("01 000C 16 00 0000002A 0001 00 0000 0578 FEC4")
    );
    assert_eq!(
        command::record_by_time(1, kind::MAIN, KmbTime(0xB0A2_2E7E00))
            .encode()
            .unwrap(),
        hex("01 0009 17 00 000000B0A22E7E00 72BC")
    );
}

#[test]
fn reply_header_and_records() {
    let mut p = hex("03 AA BB CC DD EE FF 00 00 03 E8 FF FF FF 9C");
    p.extend([1, 2, 3, 4, 5, 6, 7]);
    let h = ReplyHeader::decode(&p).unwrap();
    assert_eq!(h.archive, 3);
    assert_eq!(
        h.cursor,
        Cursor {
            max_rec: 1000,
            cur_rec: -100
        }
    );
    let recs: Vec<_> = archive::records(&p, 3).collect();
    assert_eq!(recs, [&[1, 2, 3][..], &[4, 5, 6][..]]);
}

#[test]
fn cursor_runs() {
    assert_eq!(
        Cursor {
            max_rec: 10,
            cur_rec: 0
        }
        .runs(),
        []
    );
    assert_eq!(
        Cursor {
            max_rec: 10,
            cur_rec: 4
        }
        .runs(),
        vec![0..4]
    );
    let ring = Cursor {
        max_rec: 10,
        cur_rec: -3,
    };
    assert_eq!(ring.runs(), vec![8..10, 0..7]);
    assert_eq!(ring.len(), 9);
    assert_eq!(
        Cursor {
            max_rec: 10,
            cur_rec: -10
        }
        .runs(),
        vec![1..10]
    );
}

#[test]
fn record_at_time() {
    let r = RecordAtTime::decode(&hex("0000002A 000000B0A237A5C0")).unwrap();
    assert_eq!(r.slot, Some(42));
    assert_eq!(r.time, KmbTime(0xB0_A237_A5C0));
    assert_eq!(
        RecordAtTime::decode(&hex("FFFFFFFF 0000000000000000"))
            .unwrap()
            .slot,
        None
    );
    assert_eq!(
        archive::LAST_RECORD_TIME.to_be_bytes(),
        *hex("0000E59B67503000").as_slice()
    );
}

#[test]
fn geometry() {
    assert_eq!(
        Geometry::uni(7000, 10, 60, true),
        Geometry {
            per_frame: 115,
            frames: 1
        }
    );
    assert_eq!(
        Geometry::uni(7000, 10, 60, false),
        Geometry {
            per_frame: 115,
            frames: 10
        }
    );
    assert_eq!(Geometry::uni(7000, 1, 9000, false).per_frame, 1);
    let g = Geometry {
        per_frame: 10,
        frames: 3,
    };
    assert_eq!(
        g.batches(5..72),
        vec![
            (5, g),
            (35, g),
            (
                65,
                Geometry {
                    per_frame: 7,
                    frames: 1
                }
            ),
        ]
    );
    assert_eq!(
        g.batches(0..25),
        vec![
            (
                0,
                Geometry {
                    per_frame: 10,
                    frames: 2
                }
            ),
            (
                20,
                Geometry {
                    per_frame: 5,
                    frames: 1
                }
            )
        ]
    );
}

fn field(name: &str, type_code: u8, pb: u16) -> ArchiveField {
    ArchiveField {
        name: name.into(),
        ic: 6,
        ics: 0,
        icss: 0,
        info1: 0,
        info2: 0,
        type_code,
        pb,
        zapis: 1,
        zapis2: None,
    }
}

fn desc(fields: Vec<ArchiveField>) -> ArchiveDescription {
    let group = ArchiveGroup {
        idx: 6,
        idxs: 0,
        idxss: 0,
        typ: 0,
        k: 1.0,
        unit: String::new(),
        name: "Main".into(),
    };
    ArchiveDescription {
        groups: vec![group],
        fields,
    }
}

#[test]
fn record_9_4() {
    let d = desc(vec![
        field("Length", 1, 1),
        field("Sum", 1, 1),
        field("Time", 19, 1),
        field("U1", 4, 1),
    ]);
    let version = uni::header_version(&d.fields, None);
    assert_eq!(version, 1);
    let layout = Layout::new(&d, kind::MAIN, version, uni::DEFAULT_MAX_ARCH_SIZE).unwrap();
    assert_eq!(layout.record_len, 16);
    let rec = hex("0010 0E9A 000000B0A237A5C0 43660000");
    assert_eq!(uni::sum(&rec), 0x0E9A);
    assert_eq!(layout.check(&rec), Ok(()));
    assert_eq!(layout.time(&rec), Some(KmbTime(0xB0_A237_A5C0)));
    let values = layout.decode(&rec).unwrap();
    assert_eq!(values[3], ("U1".to_string(), Value::F32(230.0)));

    let mut bad = rec;
    bad[15] ^= 1;
    assert_eq!(layout.check(&bad), Err(Reject::Sum));
    assert_eq!(Reject::Sum.reason(), 16);
}

#[test]
fn record_9_5() {
    let d = desc(vec![
        field("Length", 1, 1),
        field("Sum", 1, 1),
        field("AId", 2, 1),
        field("Ecc", 10, 3),
        field("Time", 19, 1),
        field("P1", 4, 1),
        field("P2", 4, 1),
        field("N", 2, 1),
        field("B", 0, 1),
    ]);
    assert_eq!(uni::header_version(&d.fields, None), 3);
    assert_eq!(uni::header_version(&d.fields, Some(4)), 4);
    let layout = Layout::new(&d, kind::MAIN, 4, uni::DEFAULT_MAX_ARCH_SIZE).unwrap();
    assert_eq!(
        (layout.record_len, layout.ecc_len, layout.time_offset()),
        (32, 3, 11)
    );
    let rec = hex("0020 D4DA 00000001 0FFFF3 000000B0A237A5C0 43660000 40A00000 0000000A 07");
    assert_eq!(uni::ecc(&rec, 3), hex("0FFFF3"));
    assert_eq!(uni::sum(&rec), 0xD4DA);
    assert_eq!(layout.check(&rec), Ok(()));

    let mut flipped = rec.clone();
    flipped[25] ^= 0x10;
    assert_eq!(layout.check(&flipped), Err(Reject::Ecc));
    let mut erased = rec;
    erased[0] = 0xFF;
    erased[1] = 0xFF;
    assert_eq!(layout.check(&erased), Err(Reject::Erased));
}

#[test]
fn ecc_zero_block() {
    assert_eq!(uni::ecc_block(&[0; 512]), [0xFF, 0xFF, 0xFF]);
}

#[test]
fn time_checks() {
    let d = desc(vec![field("Length", 1, 1), field("Time", 19, 1)]);
    let layout = Layout::new(&d, kind::MAIN, 0, 15000).unwrap();
    assert_eq!(
        layout.check(&hex("000A 0000000000000000")),
        Err(Reject::TimeZero)
    );
    assert_eq!(
        layout.check(&hex("000A FFFFFFFFFFFFFFFF")),
        Err(Reject::TimeInvalid)
    );
    assert_eq!(layout.check(&hex("000A 000002DEC1F42C00")), Ok(()));
    assert_eq!(
        layout.check(&hex("000A 000002DEC1F42C01")),
        Err(Reject::TimeAfter2100)
    );
    assert_eq!(
        layout.check(&hex("000B 0000000000000001")),
        Err(Reject::Length)
    );
}

#[test]
fn layout_errors() {
    let d = desc(vec![field("Time", 19, 1), field("Length", 1, 1)]);
    assert!(Layout::new(&d, kind::MAIN, 0, 15000).is_err());
    let d = desc(vec![field("Length", 1, 1), field("Time", 19, 1)]);
    assert!(Layout::new(&d, kind::LOG, 0, 15000).is_err());
    assert!(Layout::new(&d, kind::MAIN, 0, 10).is_err());
    assert!(Layout::new(&d, kind::MAIN, 5, 15000).is_err());
}

#[test]
fn runs_from() {
    let ring = Cursor {
        max_rec: 10,
        cur_rec: -3,
    };
    assert_eq!(ring.runs_from(9), vec![9..10, 0..7]);
    assert_eq!(ring.runs_from(2), vec![2..7]);
    assert_eq!(ring.runs_from(7), []);
}

#[test]
fn columns() {
    let mut u1 = field("U1", 4, 1);
    u1.ics = 1;
    u1.info2 = 3;
    let mut hu = field("U1", 13, 2);
    hu.ics = 13;
    hu.icss = 1;
    let mut d = desc(vec![field("Length", 1, 1), field("Time", 19, 1), u1, hu]);
    let sub = |idxs, idxss, k, unit: &str, name: &str| ArchiveGroup {
        idx: 6,
        idxs,
        idxss,
        typ: 0,
        k,
        unit: unit.into(),
        name: name.into(),
    };
    d.groups.push(sub(1, 0, 0.25, "V", "U"));
    d.groups.push(sub(13, 0, 1.0, " ", "Harmonics/Uh"));
    d.groups.push(sub(13, 1, 1.0, "V", "U1"));
    let layout = Layout::new(&d, kind::MAIN, 0, 15000).unwrap();
    let cols = layout.columns(&d);
    assert_eq!(cols[2].name, "U_U1");
    assert_eq!(cols[2].stat, Some(uni::Stat::Max));
    assert_eq!((cols[2].unit.as_str(), cols[2].k), ("V", 0.25));
    assert_eq!(cols[2].scaled(&Value::F32(1000.0)), Some(250.0));
    assert_eq!(cols[3].name, "Harmonics/Uh_U1_U1");
    assert_eq!(cols[3].unit, "V");
    assert_eq!(cols[0].name, "Length");
}

#[test]
fn unit_in_name() {
    let d = desc(vec![
        field("Length", 1, 1),
        field("Time", 19, 1),
        field("+Ai[Wh", 5, 1),
    ]);
    let layout = Layout::new(&d, kind::MAIN, 0, 15000).unwrap();
    let cols = layout.columns(&d);
    assert_eq!(
        (cols[2].name.as_str(), cols[2].unit.as_str()),
        ("+Ai", "Wh")
    );
}

#[test]
fn check_narrow_header_fields() {
    let d = desc(vec![field("Length", 1, 1), field("Time", 0, 1)]);
    let layout = Layout::new(&d, kind::MAIN, 0, 15000).unwrap();
    assert_eq!(layout.record_len, 3);
    assert!(layout.check(&hex("0003 01")).is_err());
    assert!(layout.time(&hex("0003 01")).is_none());
    let d = desc(vec![field("Length", 10, 0), field("Time", 0, 1)]);
    let layout = Layout::new(&d, kind::MAIN, 0, 15000).unwrap();
    assert_eq!(layout.record_len, 1);
    assert!(layout.check(&hex("01")).is_err());
    let d = desc(vec![
        field("Length", 0, 1),
        field("Sum", 0, 1),
        field("Time", 0, 1),
    ]);
    let layout = Layout::new(&d, kind::MAIN, 1, 15000).unwrap();
    assert_eq!(layout.record_len, 3);
    assert!(layout.check(&hex("0003 01")).is_err());
}

#[test]
fn geometry_large_reply_count() {
    let g = Geometry::uni(7200, 256, 100, false);
    assert!(g.frames >= 1);
    let batches = g.batches(0..1000);
    let mut next = 0;
    for (start, b) in &batches {
        assert_eq!(*start, next);
        assert!(b.per_frame >= 1 && b.frames >= 1);
        next += u32::from(b.per_frame) * u32::from(b.frames);
    }
    assert_eq!(next, 1000);
}

#[test]
fn batches_zero_geometry() {
    let g = Geometry {
        per_frame: 0,
        frames: 0,
    };
    let batches = g.batches(0..5);
    let mut next = 0;
    for (start, b) in &batches {
        assert_eq!(*start, next);
        assert!(b.per_frame >= 1 && b.frames >= 1);
        next += u32::from(b.per_frame) * u32::from(b.frames);
    }
    assert_eq!(next, 5);
}
