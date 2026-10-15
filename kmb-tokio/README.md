# kmb-tokio

An async client on [Tokio](https://tokio.rs) for PQplus and KMB power
quality meters (UMD-98 and the SMP family), built on the sans-IO protocol
crate [`kmb`](https://github.com/Project-Stateful-Zenith/zenith-kmb).

It connects over TCP (port 2101) or, with the `tls` feature, over TLS
(port 7101), logs in, unwraps encrypted links, and turns requests into
replies: identify, clock read and adjust, configuration and live values,
and archive downloads that read only the records asked for.

## Example

```rust,no_run
use kmb::archive::uni::{self, Layout};
use kmb::uni::DataSet;
use kmb::KmbTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut meter = kmb_tokio::connect("192.0.2.10:2101", 1).await?;

    let id = meter.identify().await?;
    println!("serial {} firmware {}", id.device_no, id.firmware_version());
    println!("clock {:?}", meter.read_clock().await?.time.to_unix_ms());

    let config = meter.read_description(DataSet::Config).await?;
    let archives = meter.read_archive_description().await?;
    let arch_ver = config.value("Message", "ArchVer").and_then(|v| v.as_u64());
    let version = uni::header_version(&archives.fields, arch_ver.and_then(|v| v.try_into().ok()));
    let main = Layout::new(&archives, 0, version, uni::DEFAULT_MAX_ARCH_SIZE)?;

    let hour_ago = KmbTime(kmb_tokio::now().0.saturating_sub(3_600_000));
    for record in meter.download_after(&config, &main, hour_ago).await? {
        if let Ok(bytes) = &record.bytes {
            println!("{:?}: {:?}", main.time(bytes), main.decode(bytes)?);
        }
    }
    Ok(())
}
```

For a meter with a login, call `meter.set_credentials(user, password)`
before the first command; for an encrypted link, `meter.set_keys(...)`
with a lookup that returns the meter's PSK. Over TLS, `tls::connect_tls`
takes the trust to check the meter's certificate against: a root CA key,
certificate pins, or both. No root key is built in.

## Features

| Feature | Adds |
| --- | --- |
| `tls` | `kmb_tokio::tls`: KMB over TLS with rustls |

## License

Apache-2.0. Copyright 2026 Project-Stateful-Zenith Contributors.
