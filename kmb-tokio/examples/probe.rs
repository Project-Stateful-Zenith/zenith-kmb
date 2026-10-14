use kmb::archive::uni::{self, Layout};
use kmb::envelope::Psk;
use kmb::uni::{DataSet, Description, Value};
use kmb::{Identify, KmbTime};
use kmb_tokio::Client;
use std::error::Error;

struct Args {
    host: String,
    address: u8,
    records: u32,
    user: Option<(String, String)>,
    psk: Option<Psk>,
    tls_root: Option<String>,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut it = std::env::args().skip(1);
    let host = it.next().ok_or("usage: probe HOST:PORT [options]")?;
    let mut args = Args {
        host,
        address: 1,
        records: 3,
        user: None,
        psk: None,
        tls_root: None,
    };
    let mut user = None;
    let mut password = None;
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--address" => args.address = value.parse()?,
            "--records" => args.records = value.parse()?,
            "--user" => user = Some(value),
            "--password" => password = Some(value),
            "--psk" => args.psk = Some(Psk::from_base64(&value)?),
            "--tls-root" => args.tls_root = Some(value),
            _ => return Err(format!("unknown option {flag}").into()),
        }
    }
    if let (Some(u), Some(p)) = (user, password) {
        args.user = Some((u, p));
    }
    Ok(args)
}

fn time(t: KmbTime) -> String {
    let civil_time = |ms: i64| {
        let secs = ms.div_euclid(1000);
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, m, d) = civil(days)?;
        Some(format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:03} UTC",
            rem / 3600,
            rem / 60 % 60,
            rem % 60,
            ms.rem_euclid(1000)
        ))
    };
    t.to_unix_ms()
        .and_then(civil_time)
        .unwrap_or_else(|| "invalid".into())
}

fn civil(z: i64) -> Option<(i64, i64, i64)> {
    let z = z.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .checked_sub(doe / 1460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = era
        .checked_mul(400)?
        .checked_add(yoe)?
        .checked_add(i64::from(m <= 2))?;
    Some((y, m, d))
}

fn show_identify(id: &Identify) {
    println!("identify:");
    println!("  device_no        {}", id.device_no);
    println!(
        "  device_type      {:#06X} ({:?})",
        id.device_type,
        id.family()
    );
    println!("  props_type       {}", id.props_type);
    println!(
        "  software_version {:#06X} ({})",
        id.software_version,
        id.firmware_version()
    );
    println!("  hardware_version {}", id.hardware_version);
    println!(
        "  software_modules {:#06X} (universal: {})",
        id.software_modules,
        id.is_universal()
    );
    println!("  device_addr      {}", id.device_addr);
    println!("  bootloader       {}", id.bootloader());
    println!("  sub_device_type  {:04X?}", id.sub_device_type);
    if let Some(n) = &id.name {
        println!("  name             {n:?}");
    }
    if let Some(a) = &id.archive_def {
        println!("  archive_def      {a:?}");
    }
}

fn show_description(label: &str, d: &Description) {
    let read = d.values.iter().filter(|v| v.is_some()).count();
    println!(
        "{label}: {} groups, {} fields, {read} values",
        d.groups.len(),
        d.fields.len()
    );
    for g in &d.groups {
        let n = d.fields.iter().filter(|f| f.ic == g.idx).count();
        println!("  group {:3} {:<20} {n} fields", g.idx, g.name);
    }
}

fn show_config(config: &Description) {
    show_description("config", config);
    for name in [
        "Cnfgchange",
        "CommBufLen",
        "ArcReplyCnt",
        "MaxArchSize",
        "ArchVer",
        "GUI_ACT",
    ] {
        println!("  Message/{name:<12} {:?}", config.value("Message", name));
    }
    for (group, name) in [("Identify", "ProjectVersion"), ("Identify", "CPU")] {
        println!("  {group}/{name:<14} {:?}", config.value(group, name));
    }
}

fn config_u64(config: &Description, name: &str) -> Option<u64> {
    config.value("Message", name).and_then(Value::as_u64)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    println!(
        "connecting to {} address {} (TLS {})",
        args.host,
        args.address,
        args.tls_root.is_some()
    );
    if let Some(root) = &args.tls_root {
        #[cfg(feature = "tls")]
        {
            let (x, y) = kmb_tokio::tls::parse_p256_point(root)
                .ok_or("--tls-root is not an uncompressed P-256 point in hex")?;
            let trust = kmb_tokio::tls::Trust::Root(x, y);
            let c = kmb_tokio::tls::connect_tls(args.host.as_str(), args.address, trust).await?;
            println!("TLS: the meter's chain verified against the given root CA");
            return run(c, args).await;
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = root;
            return Err("--tls-root needs the tls feature: cargo run --features tls ...".into());
        }
    }
    let c = kmb_tokio::connect(args.host.as_str(), args.address).await?;
    run(c, args).await
}

async fn run<S>(mut c: Client<S>, args: Args) -> Result<(), Box<dyn Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Some((u, p)) = &args.user {
        c.set_credentials(u, p);
    }
    if let Some(psk) = args.psk.clone() {
        c.set_keys(Box::new(move |_| Some(psk.clone())));
    }

    let id = c.identify().await?;
    show_identify(&id);
    println!("  encrypted        {}", c.is_encrypted());

    match c.read_clock().await {
        Ok(rtc) => println!("clock: {} (extra {:?})", time(rtc.time), rtc.extra),
        Err(e) => println!("clock: {e}"),
    }

    if !id.is_universal() {
        println!("not a universal-config meter; the classic structures are not in this probe");
        return Ok(());
    }

    let config = c.read_description(DataSet::Config).await?;
    show_config(&config);

    match c.read_description(DataSet::Status).await {
        Ok(status) => show_description("status", &status),
        Err(e) => println!("status: {e}"),
    }

    let arch = c.read_archive_description().await?;
    println!(
        "archive descriptors: {} groups, {} fields",
        arch.groups.len(),
        arch.fields.len()
    );
    let arch_ver = config_u64(&config, "ArchVer").and_then(|v| u32::try_from(v).ok());
    let version = uni::header_version(&arch.fields, arch_ver);
    let max_size = config_u64(&config, "MaxArchSize").map_or(uni::DEFAULT_MAX_ARCH_SIZE, |v| {
        usize::try_from(v).unwrap_or(usize::MAX)
    });
    println!("  header version {version} (ArchVer {arch_ver:?}), MaxArchSize {max_size}");

    for g in arch.groups.iter().filter(|g| g.idxs == 0 && g.idxss == 0) {
        let archive = (0..=u8::MAX).find(|&t| uni::archive_name(t) == Some(g.name.as_str()));
        let stored = arch
            .fields
            .iter()
            .filter(|f| f.ic == g.idx && f.zapis != 0)
            .count();
        print!(
            "  archive {:<16} idx {:3} typ {:3} k {} unit {:?}: {stored} stored fields",
            g.name, g.idx, g.typ, g.k, g.unit
        );
        let Some(archive) = archive else {
            println!(", no archive type");
            continue;
        };
        let layout = match Layout::new(&arch, archive, version, max_size) {
            Ok(l) => l,
            Err(e) => {
                println!(", layout: {e}");
                continue;
            }
        };
        let cursor = match c.probe_archive(archive).await {
            Ok(cursor) => cursor,
            Err(e) => {
                println!(", R {}, probe: {e}", layout.record_len);
                continue;
            }
        };
        println!(
            ", type {archive}, R {}, maxRec {}, curRec {}, {} written",
            layout.record_len,
            cursor.max_rec,
            cursor.cur_rec,
            cursor.len()
        );
        let Some(last) = cursor.runs().last().cloned() else {
            continue;
        };
        let from = last.end.saturating_sub(args.records).max(last.start);
        let geometry = c.geometry(&config, &layout);
        let columns = layout.columns(&arch);
        match c.read_records(&layout, from..last.end, geometry).await {
            Ok(records) => {
                for r in records {
                    show_record(&layout, &columns, version, &r);
                }
            }
            Err(e) => println!("    records: {e}"),
        }
    }
    Ok(())
}

fn show_record(layout: &Layout, columns: &[uni::Column], version: u32, r: &kmb_tokio::Record) {
    let bytes = match &r.bytes {
        Ok(bytes) => bytes,
        Err(reject) => {
            println!("    slot {:6} rejected: {reject}", r.slot);
            return;
        }
    };
    let t = layout.time(bytes).map(time).unwrap_or_default();
    let values = layout.decode(bytes).map_or(0, |v| v.len());
    println!("    slot {:6} {t} ({values} fields)", r.slot);
    let Ok(fields) = layout.decode(bytes) else {
        return;
    };
    let header = if version >= 3 {
        5
    } else {
        usize::try_from(version).map_or(5, |v| v.saturating_add(2))
    };
    for ((_, v), col) in fields.iter().zip(columns).skip(header).take(6) {
        let stat = col.stat.map_or("", |s| s.as_str());
        match col.scaled(v) {
            Some(x) => println!("      {} {stat} = {x} {}", col.name, col.unit),
            None => println!("      {} {stat} = {v:?} {}", col.name, col.unit),
        }
    }
}
