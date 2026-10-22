<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/banner-light.svg">
    <img alt="Zenith KMB" src=".github/assets/banner-dark.svg" width="100%">
  </picture>
</p>

# zenith-kmb

A Rust library for talking to **PQplus and KMB power quality meters** (UMD-98
and the SMP family) over their native KMB/KMP protocol: identify a meter,
read and set its clock, read its configuration and live values, and
download its archives (measurements, energy, events, power quality).

It is the protocol layer of [kmb-sync](https://github.com/Project-Stateful-Zenith/kmb-sync),
an always-on collector service built on it.

| Crate | Use |
| --- | --- |
| `kmb` | the protocol core: frames, checksums, login, encryption, commands, and decoders for identify, clock, configuration and archive records |
| `kmb-tokio` | an async client on Tokio that sends the commands and reassembles the replies; feature `tls` adds KMB over TLS |

> [!NOTE]
> This repository is a clone of an internal production repository. It may
> lag behind the internal one in releases and patches, though we try to
> patch issues here that we catch internally.

## How it is built

`kmb` is **sans-IO**. It opens no sockets, reads no clock and has no
runtime: you hand it the bytes you received and it returns the frames to
send and the decoded messages. That keeps it testable byte for byte and
usable from any transport (TCP, TLS, a serial gateway, a test harness).
`kmb-tokio` is one such transport. `unsafe` code is forbidden in both
crates.

What the protocol covers:

- **Framing**: addressed frames with a CRC-16, split and reassembled
  across TCP reads.
- **Access**: the PIN login meters with a user and password expect, and
  the encrypted envelope (AES-128-CBC with HMAC-SHA256, keyed by a per-meter
  PSK) of meters that require it. The PIN is the vendor's MD5-derived
  32-bit value and is weak on its own; the envelope or TLS is what protects
  the link.
- **Universal configuration**: meters describe their own data. The client
  reads those descriptions first and decodes configuration, status, live
  values and archive records from them, so new fields need no code change.
- **Archives**: each archive is a ring buffer on the meter. The client
  finds where a time falls in the ring, reads only the slots it needs in
  batches that fit the meter's buffer, and checks every record (length,
  checksum, time) before handing it out.

## Example

```rust
use kmb::archive::uni::{self, Layout};
use kmb::uni::DataSet;
use kmb::KmbTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Meter at 192.0.2.10, bus address 1, port 2101.
    let mut meter = kmb_tokio::connect("192.0.2.10:2101", 1).await?;

    let id = meter.identify().await?;
    println!("serial {} firmware {}", id.device_no, id.firmware_version());
    println!("clock {:?}", meter.read_clock().await?.time.to_unix_ms());

    // Archive layout, read from the meter itself.
    let config = meter.read_description(DataSet::Config).await?;
    let archives = meter.read_archive_description().await?;
    let arch_ver = config.value("Message", "ArchVer").and_then(|v| v.as_u64());
    let version = uni::header_version(&archives.fields, arch_ver.and_then(|v| v.try_into().ok()));
    let main = Layout::new(&archives, 0, version, uni::DEFAULT_MAX_ARCH_SIZE)?;

    // Every record of the Main archive written in the last hour.
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
before the first command; for an encrypted meter, `meter.set_keys(...)`
with a lookup that returns its PSK.

## Command-line examples

`kmb-tokio/examples` has three small tools that also serve as worked
examples. They only read from the meter unless an option says otherwise.

```sh
# Identify a meter, read its clock, configuration and the newest records of every archive
cargo run --example probe -- 192.0.2.10:2101 --records 3
cargo run --example probe -- 192.0.2.10:2101 --user admin --password 1234
cargo run --example probe -- 192.0.2.10:2101 --psk BASE64_PSK
cargo run --features tls --example probe -- 192.0.2.10:7101 --tls-root 04HEX...

# Clock offset between meter and PC; --adjust sets the meter clock
cargo run --example clock -- 192.0.2.10:2101
cargo run --example clock -- 192.0.2.10:2101 --adjust

# Send raw commands (number:payload in hex) and print the frames; here identify and read clock
cargo run --example raw -- 192.0.2.10:2101 1: 17:
```

## Build

```sh
cargo build --workspace
cargo test --workspace --all-features
```

Rust 1.88 or newer. The tests run against recorded frames and an
in-process fake meter; no hardware is needed.

## Disclaimer

> [!WARNING]
> This project is an independent implementation, made for interoperability
> with meters its users own or operate. The code was written from a
> separately prepared specification of the protocol. No vendor source code
> is contained in or was copied into this repository, and no vendor keys,
> certificates or product tables are included: for KMB over TLS you supply
> the root CA public key or certificate fingerprints yourself.
>
> This project is not affiliated with, endorsed by or supported by the
> manufacturers of the meters or of their PC software. All product names
> and trademarks belong to their respective owners and are used only to
> identify the devices this software works with.
>
> The software is provided "as is", without warranty of any kind. Use it at
> your own risk, especially when writing to meters.

## License

Apache-2.0, see [LICENSE](LICENSE).
Copyright 2026 Project-Stateful-Zenith Contributors.
