#![forbid(unsafe_code)]

#[cfg(feature = "tls")]
pub mod tls;

use kmb::archive::uni::{Layout, Reject};
use kmb::archive::{self, Cursor, Geometry, RecordAtTime, ReplyHeader};
use kmb::command;
use kmb::envelope::{self, Handshake, Psk, uid_string};
use kmb::uni::{self, ArchiveDescription, DataSet, Description, Page, Value, rezim};
use kmb::{DecodeError, EnvelopeError, ErrorCode, Frame, FrameDecoder, FrameError};
use kmb::{Identify, KmbTime, Reply, Rtc, pin};
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

pub const PORT: u16 = 2101;
pub const TLS_PORT: u16 = 7101;
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(5000);
pub const BYTE_TIMEOUT: Duration = Duration::from_millis(10_000);
pub const SETTLE: Duration = Duration::from_millis(300);
pub const PAGE_ATTEMPTS: usize = 4;
pub const BATCH_FOLLOW_UPS: usize = 9;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Timeout,
    Closed,
    Frame(FrameError),
    WrongAddress(u8),
    Envelope(EnvelopeError),
    NoKey(String),
    UnsupportedEnvelope(u8),
    KeyRejected(Option<String>),
    Device { command: u8, code: ErrorCode },
    NoData,
    NotAcknowledged,
    Decode(DecodeError),
    Precondition(&'static str),
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Timeout => f.write_str("reply timed out"),
            Self::Closed => f.write_str("connection closed"),
            Self::Frame(e) => write!(f, "bad frame: {e}"),
            Self::WrongAddress(a) => write!(f, "reply from address {a}"),
            Self::Envelope(e) => write!(f, "envelope: {e}"),
            Self::NoKey(uid) => write!(f, "meter {uid} wants encryption, no key known"),
            Self::UnsupportedEnvelope(v) => write!(f, "envelope version {v} is not supported"),
            Self::KeyRejected(uid) => match uid {
                Some(uid) => write!(f, "meter {uid} rejected the key"),
                None => f.write_str("meter rejected the key"),
            },
            Self::Device { command, code } => write!(f, "command {command} refused: {code}"),
            Self::NoData => f.write_str("meter has no data"),
            Self::NotAcknowledged => f.write_str("set not acknowledged"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::Precondition(what) => f.write_str(what),
            Self::Random => f.write_str("random source failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<EnvelopeError> for Error {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub type KeyLookup = Box<dyn Fn(&str) -> Option<Psk> + Send + Sync>;

pub async fn connect(addr: impl ToSocketAddrs, address: u8) -> Result<Client<TcpStream>> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout)??;
    stream.set_nodelay(true)?;
    tokio::time::sleep(SETTLE).await;
    let mut client = Client::new(stream, address);
    client.one_frame_archives = true;
    Ok(client)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub slot: u32,
    pub bytes: std::result::Result<Vec<u8>, Reject>,
}

pub struct Client<S> {
    io: S,
    decoder: FrameDecoder,
    address: u8,
    byte_timeout: Duration,
    user_hash: u32,
    identify: Option<Identify>,
    psk: Option<Psk>,
    uid: Option<String>,
    keys: Option<KeyLookup>,
    one_frame_archives: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    pub fn new(io: S, address: u8) -> Self {
        Self {
            io,
            decoder: FrameDecoder::new(),
            address,
            byte_timeout: BYTE_TIMEOUT,
            user_hash: 0,
            identify: None,
            psk: None,
            uid: None,
            keys: None,
            one_frame_archives: false,
        }
    }

    pub const fn set_byte_timeout(&mut self, timeout: Duration) {
        self.byte_timeout = timeout;
    }

    pub fn set_credentials(&mut self, user: &str, password: &str) {
        self.user_hash = pin::user_hash(user, password);
    }

    pub fn set_keys(&mut self, keys: KeyLookup) {
        self.keys = Some(keys);
    }

    pub const fn set_one_frame_archives(&mut self, on: bool) {
        self.one_frame_archives = on;
    }

    #[must_use]
    pub const fn identity(&self) -> Option<&Identify> {
        self.identify.as_ref()
    }

    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.psk.is_some()
    }

    pub fn pin(&self) -> u32 {
        self.identify
            .as_ref()
            .map_or(0, |id| pin::wire_pin(self.user_hash, id.device_no))
    }

    pub fn into_inner(self) -> S {
        self.io
    }

    async fn send(&mut self, frame: &Frame) -> Result<()> {
        let wire = match &self.psk {
            Some(psk) => {
                let mut random = [0; envelope::RANDOM_LEN];
                getrandom::fill(&mut random).map_err(|_| Error::Random)?;
                envelope::wrap(psk, &random, frame)?
            }
            None => frame.clone(),
        };
        self.io.write_all(&wire.encode()?).await?;
        self.io.flush().await?;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Frame> {
        let mut buf = [0; 8192];
        loop {
            if let Some(frame) = self.decoder.next_frame() {
                return Ok(frame?);
            }
            let n = tokio::time::timeout(self.byte_timeout, self.io.read(&mut buf))
                .await
                .map_err(|_| Error::Timeout)??;
            if n == 0 {
                return Err(Error::Closed);
            }
            let got = buf.get(..n).ok_or(Error::Closed)?;
            self.decoder.push(got);
        }
    }

    pub async fn exchange(&mut self, frame: &Frame, replies: usize) -> Result<Vec<Frame>> {
        self.decoder.clear();
        self.send(frame).await?;
        let n = if self.psk.is_some() {
            1
        } else {
            replies.max(1)
        };
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let mut reply = self.read_frame().await?;
            if reply.command == envelope::ENVELOPE_COMMAND {
                let psk = self
                    .psk
                    .as_ref()
                    .ok_or(EnvelopeError::NotEnvelope(reply.command))?;
                reply = envelope::unwrap(psk, &reply)?;
            }
            if reply.address != frame.address {
                self.decoder.clear();
                return Err(Error::WrongAddress(reply.address));
            }
            out.push(reply);
        }
        Ok(out)
    }

    fn handshake(&mut self, data: &[u8]) -> Result<()> {
        let hs = Handshake::parse(data)?;
        if !hs.is_supported() {
            return Err(Error::UnsupportedEnvelope(hs.version));
        }
        let uid = uid_string(&hs.uid);
        let psk = self.keys.as_ref().and_then(|k| k(&uid));
        self.uid = Some(uid.clone());
        self.psk = Some(psk.ok_or(Error::NoKey(uid))?);
        Ok(())
    }

    async fn call(&mut self, frame: &Frame) -> Result<Frame> {
        let mut handshaken = false;
        loop {
            let reply = self.exchange(frame, 1).await?.remove(0);
            if let Ok(Reply::Error {
                command,
                code,
                data,
            }) = reply.reply()
            {
                match code {
                    ErrorCode::EncryptionRequired if !handshaken && self.psk.is_none() => {
                        self.handshake(data)?;
                        handshaken = true;
                        continue;
                    }
                    ErrorCode::KeyInvalid => return Err(Error::KeyRejected(self.uid.clone())),
                    _ => return Err(Error::Device { command, code }),
                }
            }
            return Ok(reply);
        }
    }

    pub async fn get(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        let reply = self.call(frame).await?;
        match reply.reply() {
            Ok(Reply::Data(payload)) => Ok(payload.to_vec()),
            Ok(Reply::NoData) => Err(Error::NoData),
            Ok(Reply::Error { command, code, .. }) => Err(Error::Device { command, code }),
            Err(_) => Err(Error::Decode(DecodeError::Length {
                structure: "reply",
                len: 0,
            })),
        }
    }

    pub async fn set(&mut self, frame: &Frame) -> Result<()> {
        let reply = self.call(frame).await?;
        if reply.is_ack() {
            Ok(())
        } else {
            Err(Error::NotAcknowledged)
        }
    }

    pub async fn identify(&mut self) -> Result<Identify> {
        let payload = self.get(&command::identify(self.address)).await?;
        let id = Identify::decode(&payload)?;
        self.identify = Some(id.clone());
        Ok(id)
    }

    pub async fn read_clock(&mut self) -> Result<Rtc> {
        let payload = self.get(&command::get_rtc(self.address)).await?;
        Ok(Rtc::decode(&payload)?)
    }

    pub async fn adjust_clock(&mut self) -> Result<KmbTime> {
        let id = self
            .identify
            .as_ref()
            .ok_or(Error::Precondition("identify first"))?;
        if !id.is_universal() {
            return Err(Error::Precondition("adjust_clock is for universal meters"));
        }
        let started = Instant::now();
        self.read_clock().await?;
        let half_ms = started.elapsed().as_millis() / 2;
        let time = now().add_ms(u64::try_from(half_ms).unwrap_or(u64::MAX));
        self.set(&command::adjust_time_universal(
            self.address,
            self.pin(),
            time,
        ))
        .await?;
        Ok(time)
    }

    async fn uni_page(&mut self, set: DataSet, rezim: u8, start: u16) -> Result<Vec<u8>> {
        let frame = uni::get(
            self.address,
            self.pin(),
            set,
            rezim,
            start,
            uni::COUNT_R_ALL,
        );
        let mut last = Error::Timeout;
        for _ in 0..PAGE_ATTEMPTS {
            match self.get(&frame).await {
                Err(e @ (Error::Timeout | Error::Frame(_) | Error::NoData)) => last = e,
                other => return other,
            }
        }
        Err(last)
    }

    async fn uni_phase(
        &mut self,
        set: DataSet,
        rezim: u8,
        mut push: impl FnMut(&[u8]) -> std::result::Result<Page, DecodeError>,
    ) -> Result<()> {
        let mut start = 0;
        loop {
            let payload = self.uni_page(set, rezim, start).await?;
            match push(&payload)? {
                Page::Done => return Ok(()),
                Page::More(next) => start = next,
            }
        }
    }

    pub async fn read_description(&mut self, set: DataSet) -> Result<Description> {
        let mut d = Description::default();
        self.uni_phase(set, rezim::GROUPS, |p| d.push_groups(p))
            .await?;
        self.uni_phase(set, rezim::FIELDS, |p| d.push_fields(p))
            .await?;
        self.uni_phase(set, rezim::VALUES, |p| d.push_values(p))
            .await?;
        Ok(d)
    }

    pub async fn read_values(&mut self, set: DataSet, d: &mut Description) -> Result<()> {
        self.uni_phase(set, rezim::VALUES, |p| d.push_values(p))
            .await
    }

    pub async fn write_description(
        &mut self,
        set: DataSet,
        d: &Description,
        changed_groups: &[u8],
    ) -> Result<()> {
        for chunk in d.write_chunks(self.address, self.pin(), set)? {
            self.set(&chunk).await?;
        }
        self.set(&uni::commit(self.address, self.pin(), changed_groups))
            .await
    }

    pub async fn write_group(&mut self, set: DataSet, d: &Description, group: &str) -> Result<()> {
        let g = d.group(group).ok_or(Error::Precondition("no such group"))?;
        let id = g.idx;
        let range = d
            .group_range(group)
            .ok_or(Error::Precondition("group fields are not contiguous"))?;
        for chunk in d.write_chunks_range(self.address, self.pin(), set, range)? {
            self.set(&chunk).await?;
        }
        self.set(&uni::commit(self.address, self.pin(), &[id]))
            .await
    }

    pub async fn read_archive_description(&mut self) -> Result<ArchiveDescription> {
        let mut d = ArchiveDescription::default();
        self.uni_phase(DataSet::Archive, rezim::GROUPS, |p| d.push_groups(p))
            .await?;
        self.uni_phase(DataSet::Archive, rezim::FIELDS, |p| d.push_fields(p))
            .await?;
        Ok(d)
    }

    pub async fn probe_archive(&mut self, archive: u8) -> Result<Cursor> {
        let payload = self.get(&archive::probe(self.address, archive)).await?;
        Ok(ReplyHeader::decode(&payload)?.cursor)
    }

    pub async fn record_at_time(&mut self, archive: u8, time: KmbTime) -> Result<RecordAtTime> {
        let payload = self
            .get(&command::record_by_time(self.address, archive, time))
            .await?;
        Ok(RecordAtTime::decode(&payload)?)
    }

    pub fn geometry(&self, config: &Description, layout: &Layout) -> Geometry {
        let value = |name, default| {
            config
                .value("Message", name)
                .and_then(Value::as_u64)
                .map_or(default, |v| u32::try_from(v).unwrap_or(u32::MAX))
        };
        Geometry::uni(
            value("CommBufLen", archive::DEFAULT_COMM_BUF_LEN),
            value("ArcReplyCnt", archive::DEFAULT_ARC_REPLY_CNT),
            layout.record_len,
            self.one_frame_archives || self.psk.is_some(),
        )
    }

    async fn read_batch(
        &mut self,
        layout: &Layout,
        start: u32,
        g: Geometry,
    ) -> Result<Vec<Record>> {
        let frames = if self.psk.is_some() { 1 } else { g.frames };
        let request = archive::request(self.address, layout.archive, start, g.per_frame, frames);
        let replies = self.exchange(&request, usize::from(frames)).await?;
        let mut out = Vec::new();
        let mut slots = start..=u32::MAX;
        for reply in replies {
            let payload = match reply.reply() {
                Ok(Reply::Data(p)) => p,
                Ok(Reply::Error { command, code, .. }) => {
                    return Err(Error::Device { command, code });
                }
                _ => break,
            };
            if ReplyHeader::decode(payload)?.archive != layout.archive {
                return Err(Error::Decode(DecodeError::Invalid {
                    structure: "archive reply",
                    reason: "archive type differs from the request",
                }));
            }
            for rec in archive::records(payload, layout.record_len) {
                let slot = slots.next().ok_or(Error::Decode(DecodeError::Invalid {
                    structure: "archive reply",
                    reason: "record numbered past the last slot",
                }))?;
                let bytes = layout.check(rec).map(|()| rec.to_vec());
                out.push(Record { slot, bytes });
            }
        }
        Ok(out)
    }

    pub async fn read_records(
        &mut self,
        layout: &Layout,
        run: std::ops::Range<u32>,
        geometry: Geometry,
    ) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        for (start, g) in geometry.batches(run) {
            let end =
                start.saturating_add(u32::from(g.per_frame).saturating_mul(u32::from(g.frames)));
            let mut next = start;
            let mut retried = false;
            let mut follow_ups: usize = 0;
            while next < end {
                let Some(&(s, part)) = g.batches(next..end).first() else {
                    break;
                };
                let got = self.read_batch(layout, s, part).await?;
                if !retried
                    && got
                        .iter()
                        .any(|r| r.bytes.as_ref().is_err_and(|e| *e != Reject::Erased))
                {
                    retried = true;
                    continue;
                }
                if let Some(last) = got.last() {
                    next = last.slot.saturating_add(1);
                    out.extend(got);
                }
                if next < end {
                    follow_ups = follow_ups.saturating_add(1);
                    if follow_ups > BATCH_FOLLOW_UPS {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    pub async fn download_after(
        &mut self,
        config: &Description,
        layout: &Layout,
        after: KmbTime,
    ) -> Result<Vec<Record>> {
        let cursor = self.probe_archive(layout.archive).await?;
        let found = self.record_at_time(layout.archive, after).await?;
        let Some(slot) = found.slot else {
            return Ok(Vec::new());
        };
        let mut runs = cursor.runs_from(slot);
        if found.time <= after
            && let Some(first) = runs.first_mut()
        {
            first.start = first.start.saturating_add(1);
        }
        let geometry = self.geometry(config, layout);
        let mut out = Vec::new();
        for run in runs.into_iter().filter(|r| !r.is_empty()) {
            out.extend(self.read_records(layout, run, geometry).await?);
        }
        Ok(skip_erased_start(out))
    }

    pub async fn download(&mut self, config: &Description, layout: &Layout) -> Result<Vec<Record>> {
        let cursor = self.probe_archive(layout.archive).await?;
        let geometry = self.geometry(config, layout);
        let mut out = Vec::new();
        for run in cursor.runs() {
            out.extend(self.read_records(layout, run, geometry).await?);
        }
        Ok(skip_erased_start(out))
    }
}

fn skip_erased_start(mut records: Vec<Record>) -> Vec<Record> {
    let n = records
        .iter()
        .take_while(|r| r.bytes == Err(Reject::Erased))
        .count();
    records.drain(..n);
    records
}

#[must_use]
pub fn now() -> KmbTime {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    KmbTime::from_unix_ms(i64::try_from(ms).unwrap_or(i64::MAX))
}
