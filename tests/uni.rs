use kmb::Frame;
use kmb::uni::kmbcfg::{self, Dialect};
use kmb::uni::{self, DataSet, Description, Page, TypeCode, Value, rezim};

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn data_sets() {
    assert_eq!(DataSet::Config.get_command(), 112);
    assert_eq!(DataSet::Config.set_command(), 113);
    assert_eq!(DataSet::Status.get_command(), 118);
    assert_eq!(DataSet::ActData.get_command(), 114);
    assert_eq!(DataSet::Archive.set_command(), 117);
    assert_eq!(
        (DataSet::MinDataT.get_command(), DataSet::MinDataT.cm_typ()),
        (120, 4)
    );
    assert_eq!(
        (DataSet::MaxData.get_command(), DataSet::MaxData.cm_typ()),
        (120, 1)
    );
    assert_eq!(DataSet::Edata.get_command(), 122);
    assert_eq!(DataSet::Cal.set_command(), 125);
}

#[test]
fn get_example() {
    let frame = uni::get(
        1,
        0x3039,
        DataSet::Config,
        rezim::FIELDS,
        0,
        uni::COUNT_R_ALL,
    );
    assert_eq!(
        frame,
        Frame::new(
            1,
            112,
            hex("00 00 30 39 00 00 00 00 01 00 00 00 00 00 00 FD E8")
        )
    );
    let t = uni::get(1, 0, DataSet::MaxDataT, rezim::VALUES, 5, 10);
    assert_eq!(
        t.payload,
        hex("00 00 00 00 00 00 00 03 02 00 05 00 00 00 00 00 0A")
    );
}

#[test]
fn commit_example() {
    assert_eq!(
        uni::commit(1, 0x3039, &[2]),
        Frame::new(
            1,
            113,
            hex("00 00 30 39 00 00 00 00 04 00 00 00 00 00 00 FD E8 02 FF")
        )
    );
    assert_eq!(uni::clear_archives(1, 0, &[]).payload[17..], [0xFF]);
    assert_eq!(uni::clear_archives(1, 0, &[]).command, 117);
}

#[test]
fn change_counter() {
    assert_eq!(uni::change_counter(&[15]), Ok(15));
    assert!(uni::change_counter(&[1, 2]).is_err());
}

const PHASE0: &str =
    "00 00 00 02 00 02 00 00 4D 65 73 73 61 67 65 00 02 00 49 6E 73 74 61 6C 6C 00 FF";
const PHASE1: &str = "00 00 00 03 00 03 43 6E 66 67 63 68 61 6E 67 65 00 00 00 00 01 00 55 6E 6F 6D 00 02 04 00 04 01 4E 61 6D 65 00 02 12 00 08 02";
const PHASE2: &str = "00 00 00 03 00 03 0F 43 66 00 00 53 30 31 00 00 00 00 00";
const FILE: &str = "00 15 00 00 4D 65 73 73 61 67 65 00 02 00 49 6E 73 74 61 6C 6C 00 FF 00 24 43 6E 66 67 63 68 61 6E 67 65 00 00 00 00 01 00 55 6E 6F 6D 00 02 04 00 04 01 4E 61 6D 65 00 02 12 00 08 02 43 66 00 00 53 30 31 00 00 00 00 00";

fn synthetic() -> Description {
    let mut d = Description::default();
    assert_eq!(d.push_groups(&hex(PHASE0)), Ok(Page::Done));
    assert_eq!(d.push_fields(&hex(PHASE1)), Ok(Page::Done));
    assert_eq!(d.push_values(&hex(PHASE2)), Ok(Page::Done));
    d
}

#[test]
fn synthetic_wire() {
    let d = synthetic();
    assert_eq!(d.groups.len(), 2);
    assert_eq!((d.groups[1].idx, d.groups[1].name.as_str()), (2, "Install"));
    assert_eq!(d.fields.len(), 3);
    assert_eq!(d.fields[1].typ(), TypeCode::F32);
    assert_eq!(d.fields[2].typ(), TypeCode::String);
    assert_eq!((d.fields[2].pb, d.fields[2].store), (8, 2));
    assert_eq!(d.value("Message", "Cnfgchange"), Some(&Value::U8(15)));
    assert_eq!(d.value("Install", "Unom"), Some(&Value::F32(230.0)));
    assert_eq!(
        d.value("Install", "Name"),
        Some(&Value::String("S01".into()))
    );
    assert_eq!(d.value("Message", "Unom"), None);
}

#[test]
fn synthetic_file() {
    let bytes = hex(FILE);
    assert_eq!(bytes.len(), 73);
    let (d, dialect) = kmbcfg::parse(&bytes).unwrap();
    assert_eq!(dialect, Dialect::Stored);
    assert_eq!(d.groups, synthetic().groups);
    assert_eq!(d.fields, synthetic().fields);
    assert_eq!(d.values[0], None);
    assert_eq!(d.values[1], Some(Value::F32(230.0)));
    assert_eq!(kmbcfg::write(&synthetic(), Dialect::Stored).unwrap(), bytes);

    let wire = kmbcfg::write(&synthetic(), Dialect::Wire).unwrap();
    assert_eq!(wire.len(), 74);
    let (w, dialect) = kmbcfg::parse(&wire).unwrap();
    assert_eq!(dialect, Dialect::Wire);
    assert_eq!(w, synthetic());

    let mut bad = bytes;
    bad.extend([0, 0]);
    assert!(kmbcfg::parse(&bad).is_err());
}

#[test]
fn paging_gates() {
    let p1 = hex("00 00 00 01 00 02 00 00 41 00 FF");
    let p2 = hex("00 01 00 01 00 02 05 00 42 00 FF");
    let mut d = Description::default();
    assert_eq!(d.push_groups(&p1), Ok(Page::More(1)));
    assert_eq!(d.push_groups(&p2), Ok(Page::Done));
    assert_eq!(d.groups[1].name, "B");
    assert!(d.push_groups(&p2).is_err());
    let mut e = Description::default();
    assert!(
        e.push_groups(&hex("00 00 00 03 00 02 00 00 41 00 FF"))
            .is_err()
    );
}

#[test]
fn empty_name_dropped() {
    let (_, groups) = uni::parse_groups(&hex("00 00 00 02 00 02 00 00 00 01 00 42 00 FF")).unwrap();
    assert_eq!(groups.len(), 1);
    let mut d = Description::default();
    assert!(
        d.push_groups(&hex("00 00 00 02 00 02 00 00 00 01 00 42 00 FF"))
            .is_err()
    );
}

#[test]
fn thirty_byte_name() {
    let mut p = hex("00 00 00 01 00 01");
    p.extend([b'N'; 30]);
    p.extend(hex("00 00 00 01 00"));
    let (_, fields) = uni::parse_fields(&p).unwrap();
    assert_eq!(fields[0].name.len(), 30);
    assert_eq!((fields[0].ic, fields[0].type_code, fields[0].pb), (0, 0, 1));
}

#[test]
fn type_codes() {
    assert_eq!(TypeCode::U64.width(4), 8);
    assert_eq!(TypeCode::U8.width(4), 1);
    assert_eq!(TypeCode::U32Array.width(7), 28);
    assert_eq!(TypeCode::F64Array.width(3), 24);
    assert_eq!(TypeCode::String.width(7), 7);
    assert_eq!(TypeCode::DateTime.width(5), 0);
    assert_eq!(TypeCode::DateTime.budget_width(5), 1);
    assert_eq!(TypeCode::from_wire(20), TypeCode::U8);
    assert_eq!(TypeCode::from_wire(19), TypeCode::DateTime);
    for code in 0..=19 {
        assert_eq!(TypeCode::from_wire(code).to_wire(), code);
    }
}

#[test]
fn value_encodings() {
    let cases: Vec<(TypeCode, u16, &str, Value)> = vec![
        (TypeCode::U16, 2, "08 35", Value::U16(2101)),
        (TypeCode::U32, 4, "C0 A8 01 01", Value::U32(3_232_235_777)),
        (TypeCode::S8, 1, "FE", Value::S8(-2)),
        (TypeCode::S16, 2, "FF FE", Value::S16(-2)),
        (
            TypeCode::F64,
            8,
            "40 6C C0 00 00 00 00 00",
            Value::F64(230.0),
        ),
        (
            TypeCode::U16Array,
            2,
            "00 01 00 02",
            Value::U16Array(vec![1, 2]),
        ),
        (
            TypeCode::S32Array,
            1,
            "FF FF FF FF",
            Value::S32Array(vec![-1]),
        ),
        (
            TypeCode::U8Array,
            3,
            "45 55 52",
            Value::U8Array(b"EUR".to_vec()),
        ),
        (
            TypeCode::String,
            7,
            "34 2E 32 37 2E 33 00",
            Value::String("4.27.3".into()),
        ),
        (TypeCode::DateTime, 1, "", Value::Empty),
    ];
    for (typ, pb, bytes, value) in cases {
        assert_eq!(
            Value::decode(&hex(bytes), typ, pb).unwrap(),
            value,
            "{typ:?}"
        );
        let mut out = Vec::new();
        value.write(&mut out, typ, pb).unwrap();
        assert_eq!(out, hex(bytes), "{typ:?}");
    }
    assert!(
        Value::U8Array(vec![1])
            .write(&mut Vec::new(), TypeCode::U8Array, 2)
            .is_err()
    );
    assert!(
        Value::U8(1)
            .write(&mut Vec::new(), TypeCode::U16, 2)
            .is_err()
    );
}

#[test]
fn archive_field_tail() {
    let p = hex(
        "00 00 00 02 00 02  55 31 00 06 01 00 00 00 04 00 01 01  49 00 06 00 00 00 C8 0D 00 03 01 02 AA BB",
    );
    let (cursor, fields) = uni::parse_archive_fields(&p).unwrap();
    assert_eq!(cursor.total, 2);
    assert_eq!(fields[0].name, "U1");
    assert_eq!(
        (fields[0].typ(), fields[0].pb, fields[0].zapis2.as_ref()),
        (TypeCode::F32, 1, None)
    );
    assert_eq!(fields[1].zapis2.as_deref(), Some(&[0xAA, 0xBB][..]));
    assert_eq!(fields[1].typ(), TypeCode::F32Array);
}

#[test]
fn archive_group() {
    let p = hex("00 00 00 01 00 01 06 00 00 00 01 3F 80 00 00 56 00 4D 61 69 6E 00 FF");
    let (_, groups) = uni::parse_archive_groups(&p).unwrap();
    assert_eq!(groups[0].idx, 6);
    assert_eq!((groups[0].typ, groups[0].k), (1, 1.0));
    assert_eq!(
        (groups[0].unit.as_str(), groups[0].name.as_str()),
        ("V", "Main")
    );
}

#[test]
fn write_chunks() {
    let mut d = synthetic();
    let ic = d.set_value("Install", "Unom", Value::F32(400.0)).unwrap();
    assert_eq!(ic, 2);
    assert!(d.set_value("Install", "Unom", Value::U8(1)).is_err());
    let frames = d.write_chunks(1, 0x3039, DataSet::Config).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].payload,
        hex(
            "00 00 30 39 00 00 00 00 03 00 00 00 00 00 03 FD E8 0F 43 C8 00 00 53 30 31 00 00 00 00 00"
        )
    );

    let mut big = Description::default();
    for i in 0..400 {
        big.fields.push(uni::Field {
            name: format!("F{i}"),
            ic: 0,
            type_code: 12,
            pb: 1,
            store: 1,
        });
        big.values.push(Some(Value::U32Array(vec![i])));
    }
    let frames = big.write_chunks(1, 0, DataSet::Config).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].payload[13..15], [0x01, 0x5E]);
    assert_eq!(frames[1].payload[9..11], [0x01, 0x5E]);
}

#[test]
fn group_write() {
    let d = synthetic();
    assert_eq!(d.group_range("Install"), Some(1..3));
    assert_eq!(d.group_range("Message"), Some(0..1));
    let frames = d
        .write_chunks_range(1, 0x3039, DataSet::Config, 1..3)
        .unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].payload,
        hex(
            "00 00 30 39 00 00 00 00 03 00 01 00 00 00 02 FD E8 43 66 00 00 53 30 31 00 00 00 00 00"
        )
    );
    let mut split = synthetic();
    split.fields[2].ic = 0;
    split.fields.swap(1, 2);
    assert_eq!(split.group_range("Message"), Some(0..2));
    split.fields[0].ic = 2;
    assert_eq!(split.group_range("Install"), None);
}

#[test]
fn write_chunks_start_past_u16() {
    let mut big = Description::default();
    for _ in 0..70_000 {
        big.fields.push(uni::Field {
            name: "F".into(),
            ic: 0,
            type_code: 0,
            pb: 0,
            store: 1,
        });
        big.values.push(Some(Value::U8(0)));
    }
    assert!(big.write_chunks(1, 0, DataSet::Config).is_err());
}
