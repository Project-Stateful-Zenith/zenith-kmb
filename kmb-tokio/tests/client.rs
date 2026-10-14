use kmb::archive::uni::Layout;
use kmb::archive::{Geometry, kind};
use kmb::envelope::{self, Psk};
use kmb::uni::{DataSet, Value};
use kmb::{Frame, FrameDecoder, KmbTime};
use kmb_tokio::{Client, Error};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

const IDENTIFY: &str =
    "30 39 94 00 00 30 18 D1 00 02 00 A0 01 30 00 00 00 00 00 00 00 00 00 00 02 00";
const PHASE0: &str =
    "00 00 00 02 00 02 00 00 4D 65 73 73 61 67 65 00 02 00 49 6E 73 74 61 6C 6C 00 FF";
const PHASE1: &str = "00 00 00 03 00 03 43 6E 66 67 63 68 61 6E 67 65 00 00 00 00 01 00 55 6E 6F 6D 00 02 04 00 04 01 4E 61 6D 65 00 02 12 00 08 02";
const PHASE2: &str = "00 00 00 03 00 03 0F 43 66 00 00 53 30 31 00 00 00 00 00";
const RTC: &str = "00 01 00 00 00 C4 82 39 8E 00";
const RECORD: &str = "0010 0E9A 000000B0A237A5C0 43660000";

const ARCH_PHASE0: &str = "00 00 00 01 00 01  06 00 00 0000 3F800000 00 4D 61 69 6E 00  FF";
const ARCH_PHASE1: &str = "00 00 00 04 00 04
    4C 65 6E 67 74 68 00 06 00 00 00 00 01 0001 01
    53 75 6D 00         06 00 00 00 00 01 0001 01
    54 69 6D 65 00      06 00 00 00 00 13 0001 01
    55 31 00            06 00 00 00 00 04 0001 01";

#[derive(Default)]
struct Seen {
    requests: Vec<Frame>,
}

#[cfg(test)]
fn meter(
    mut io: DuplexStream,
    seen: Arc<Mutex<Seen>>,
    mut answer: impl FnMut(&Frame) -> Vec<Frame> + Send + 'static,
) {
    tokio::spawn(async move {
        let mut dec = FrameDecoder::new();
        let mut buf = [0; 4096];
        loop {
            let n = match io.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            dec.push(&buf[..n]);
            while let Some(Ok(req)) = dec.next_frame() {
                seen.lock().unwrap().requests.push(req.clone());
                for reply in answer(&req) {
                    io.write_all(&reply.encode().unwrap()).await.unwrap();
                }
            }
        }
    });
}

#[cfg(test)]
fn plain(req: &Frame) -> Vec<Frame> {
    let a = req.address;
    let data = |p: &str| vec![Frame::new(a, req.command, hex(p))];
    match req.command {
        1 => data(IDENTIFY),
        17 => data(RTC),
        18 | 113 => vec![Frame::new(a, req.command, [0])],
        112 => match req.payload[8] {
            0 => data(PHASE0),
            1 => data(PHASE1),
            _ => data(PHASE2),
        },
        116 => match req.payload[8] {
            0 => data(ARCH_PHASE0),
            _ => data(ARCH_PHASE1),
        },
        22 => {
            let count = u16::from_be_bytes([req.payload[5], req.payload[6]]);
            let mut p = hex("00 000000000000 0000000A 00000003");
            for _ in 0..count {
                p.extend(hex(RECORD));
            }
            vec![Frame::new(a, 22, p)]
        }
        _ => vec![Frame::new(a, req.command | 0x80, [0xEE])],
    }
}

#[cfg(test)]
fn client(
    answer: impl FnMut(&Frame) -> Vec<Frame> + Send + 'static,
) -> (Client<DuplexStream>, Arc<Mutex<Seen>>) {
    let (a, b) = tokio::io::duplex(1 << 16);
    let seen = Arc::new(Mutex::new(Seen::default()));
    meter(b, seen.clone(), answer);
    (Client::new(a, 1), seen)
}

#[tokio::test]
async fn identify_sets_pin() {
    let (mut c, seen) = client(plain);
    assert_eq!(c.pin(), 0);
    let id = c.identify().await.unwrap();
    assert_eq!(id.device_no, 12345);
    assert!(id.is_universal());
    assert_eq!(c.pin(), 12345);
    c.set_credentials("admin", "1234");
    assert_eq!(c.pin(), 0x78CD_6D02);
    assert_eq!(seen.lock().unwrap().requests[0], Frame::new(1, 1, []));
}

#[tokio::test]
async fn config_description() {
    let (mut c, seen) = client(plain);
    c.identify().await.unwrap();
    let d = c.read_description(DataSet::Config).await.unwrap();
    assert_eq!(d.value("Install", "Unom"), Some(&Value::F32(230.0)));
    assert_eq!(d.value("Message", "Cnfgchange"), Some(&Value::U8(15)));
    let reqs = &seen.lock().unwrap().requests;
    assert_eq!(
        reqs[1].payload,
        hex("00 00 30 39 00 00 00 00 00 00 00 00 00 00 00 FD E8")
    );
    assert_eq!(reqs[3].payload[8], 2);
}

#[tokio::test]
async fn write_and_commit() {
    let (mut c, seen) = client(plain);
    c.identify().await.unwrap();
    let mut d = c.read_description(DataSet::Config).await.unwrap();
    let group = d.set_value("Install", "Unom", Value::F32(400.0)).unwrap();
    c.write_description(DataSet::Config, &d, &[group])
        .await
        .unwrap();
    let reqs = &seen.lock().unwrap().requests;
    let n = reqs.len();
    assert_eq!(reqs[n - 2].payload[8], 3);
    assert_eq!(
        reqs[n - 1].payload,
        hex("00 00 30 39 00 00 00 00 04 00 00 00 00 00 00 FD E8 02 FF")
    );
}

#[tokio::test]
async fn clock() {
    let (mut c, seen) = client(plain);
    c.identify().await.unwrap();
    assert_eq!(c.read_clock().await.unwrap().time, KmbTime(843_998_400_000));
    let sent = c.adjust_clock().await.unwrap();
    let reqs = &seen.lock().unwrap().requests;
    let adjust = reqs.last().unwrap();
    assert_eq!(adjust.command, 18);
    assert_eq!(adjust.payload[..10], hex("00 00 30 39 00 00 00 00 00 00"));
    assert_eq!(adjust.payload[10..], sent.to_be_bytes());
}

#[tokio::test]
async fn archive_download() {
    let (mut c, _) = client(plain);
    c.identify().await.unwrap();
    let config = c.read_description(DataSet::Config).await.unwrap();
    let desc = c.read_archive_description().await.unwrap();
    let layout = Layout::new(&desc, kind::MAIN, 1, 15000).unwrap();
    assert_eq!(layout.record_len, 16);
    assert_eq!(
        c.geometry(&config, &layout),
        Geometry {
            per_frame: 446,
            frames: 10
        }
    );
    let records = c.download(&config, &layout).await.unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records.iter().map(|r| r.slot).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert!(
        records
            .iter()
            .all(|r| r.bytes.as_deref() == Ok(&hex(RECORD)[..]))
    );
}

const RECORD4: &str = "0020 D4DA 00000001 0FFFF3 000000B0A237A5C0 43660000 40A00000 0000000A 07";

const ARCH4_PHASE1: &str = "00 00 00 09 00 09
    4C 65 6E 67 74 68 00 06 00 00 00 00 01 0001 01
    53 75 6D 00         06 00 00 00 00 01 0001 01
    41 49 64 00         06 00 00 00 00 02 0001 01
    45 63 63 00         06 00 00 00 00 0A 0003 01
    54 69 6D 65 00      06 00 00 00 00 13 0001 01
    55 31 00            06 00 00 00 00 04 0001 01
    49 31 00            06 00 00 00 00 04 0001 01
    4E 00               06 00 00 00 00 02 0001 01
    46 00               06 00 00 00 00 00 0001 01";

#[cfg(test)]
fn erased_ring(req: &Frame) -> Vec<Frame> {
    let a = req.address;
    match req.command {
        116 if req.payload[8] != 0 => vec![Frame::new(a, 116, hex(ARCH4_PHASE1))],
        22 => {
            let start = u32::from_be_bytes(req.payload[1..5].try_into().unwrap());
            let count = u16::from_be_bytes([req.payload[5], req.payload[6]]);
            let mut p = hex("00 000000000000 0000000A FFFFFFFD");
            for slot in start..start.checked_add(u32::from(count)).unwrap() {
                if slot >= 7 {
                    p.extend([0xFF; 32]);
                } else {
                    p.extend(hex(RECORD4));
                }
            }
            vec![Frame::new(a, 22, p)]
        }
        _ => plain(req),
    }
}

#[tokio::test]
async fn download_skips_erased_ring_start() {
    let (mut c, seen) = client(erased_ring);
    c.identify().await.unwrap();
    let config = c.read_description(DataSet::Config).await.unwrap();
    let desc = c.read_archive_description().await.unwrap();
    let layout = Layout::new(&desc, kind::MAIN, 4, 15000).unwrap();
    assert_eq!(layout.record_len, 32);
    let before = seen.lock().unwrap().requests.len();
    let records = c.download(&config, &layout).await.unwrap();
    assert_eq!(
        records.iter().map(|r| r.slot).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5, 6]
    );
    assert!(
        records
            .iter()
            .all(|r| r.bytes.as_deref() == Ok(&hex(RECORD4)[..]))
    );
    let archive_requests = seen.lock().unwrap().requests[before..]
        .iter()
        .filter(|r| r.command == 22)
        .count();
    assert_eq!(archive_requests, 3);
}

#[cfg(test)]
fn three_records(req: &Frame) -> Vec<Frame> {
    match req.command {
        22 => {
            let mut p = hex("00 000000000000 FFFFFFFF FFFFFFFE");
            for _ in 0..3 {
                p.extend(hex(RECORD));
            }
            vec![Frame::new(req.address, 22, p)]
        }
        _ => plain(req),
    }
}

#[tokio::test]
async fn records_past_the_last_slot_number_are_an_error() {
    let (mut c, _) = client(three_records);
    c.identify().await.unwrap();
    let desc = c.read_archive_description().await.unwrap();
    let layout = Layout::new(&desc, kind::MAIN, 1, 15000).unwrap();
    let geometry = Geometry {
        per_frame: 1,
        frames: 1,
    };
    let got = c
        .read_records(&layout, u32::MAX - 1..u32::MAX, geometry)
        .await;
    assert!(matches!(got, Err(Error::Decode(_))), "{got:?}");
}

#[tokio::test]
async fn device_error_and_no_data() {
    let (mut c, _) = client(|req| match req.command {
        31 => vec![Frame::new(1, 31, *b"Un")],
        _ => vec![Frame::new(1, req.command | 0x80, [8])],
    });
    assert!(matches!(
        c.get(&Frame::new(1, 31, [])).await,
        Err(Error::NoData)
    ));
    assert!(matches!(
        c.get(&Frame::new(1, 78, [])).await,
        Err(Error::Device {
            command: 78,
            code: kmb::ErrorCode::NoPermission
        })
    ));
}

#[tokio::test]
async fn wrong_address_and_timeout() {
    let (mut c, _) = client(|req| match req.command {
        1 => vec![Frame::new(2, 1, hex(IDENTIFY))],
        _ => vec![],
    });
    assert!(matches!(c.identify().await, Err(Error::WrongAddress(2))));
    c.set_byte_timeout(Duration::from_millis(50));
    assert!(matches!(
        c.get(&Frame::new(1, 20, [])).await,
        Err(Error::Timeout)
    ));
}

#[cfg(test)]
fn psk() -> Psk {
    Psk(std::array::from_fn(|i| u8::try_from(i).unwrap()))
}

#[tokio::test]
async fn encryption_handshake() {
    let key = psk();
    let (mut c, seen) = client(move |req| {
        if req.command != 111 {
            return vec![
                Frame::decode(&hex(
                    "01 00 0E 81 09 01 00 01 02 03 04 05 06 07 08 09 0A 0B 02 2B",
                ))
                .unwrap(),
            ];
        }
        let inner = envelope::unwrap(&key, req).unwrap();
        let reply = plain(&inner).remove(0);
        vec![envelope::wrap(&key, &[0x5A; 32], &reply).unwrap()]
    });
    c.set_keys(Box::new(|uid| {
        (uid == "0001-0203-0405-0607-0809-0A0B").then(psk)
    }));
    let id = c.identify().await.unwrap();
    assert_eq!(id.device_no, 12345);
    assert!(c.is_encrypted());
    {
        let reqs = &seen.lock().unwrap().requests;
        assert_eq!(reqs[0].command, 1);
        assert_eq!(reqs[1].command, 111);
        assert_eq!(
            envelope::unwrap(&psk(), &reqs[1]).unwrap(),
            Frame::new(1, 1, [])
        );
    }
    assert_eq!(c.read_clock().await.unwrap().time, KmbTime(843_998_400_000));
}

#[tokio::test]
async fn encryption_without_key() {
    let (mut c, _) = client(|_| {
        vec![
            Frame::decode(&hex(
                "01 00 0E 81 09 01 00 01 02 03 04 05 06 07 08 09 0A 0B 02 2B",
            ))
            .unwrap(),
        ]
    });
    match c.identify().await {
        Err(Error::NoKey(uid)) => assert_eq!(uid, "0001-0203-0405-0607-0809-0A0B"),
        other => panic!("{other:?}"),
    }
}
