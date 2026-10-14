# zenith-kmb

The KMB/KMP protocol of PQplus and KMB power quality meters (UMD-98 and the
SMP family) for Rust.

| Crate | Use |
| --- | --- |
| `kmb` | the protocol core, sans-IO: takes received bytes, returns frames to send and decoded messages |
| `kmb-tokio` | async transport and client on Tokio; feature `tls` adds KMB over TLS |

## Build

```sh
cargo build --workspace
cargo test --workspace --all-features
```

## Disclaimer

This project is an independent implementation, made for interoperability
with meters its users own or operate. The code was written from a
separately prepared specification of the protocol. No vendor source code is
contained in or was copied into this repository, and no vendor keys,
certificates or product tables are included: for KMB over TLS you supply
the root CA public key or certificate fingerprints yourself.

This project is not affiliated with, endorsed by or supported by the
manufacturers of the meters or of their PC software. All product names and
trademarks belong to their respective owners and are used only to identify
the devices this software works with.

The software is provided "as is", without warranty of any kind. Use it at
your own risk, especially when writing to meters.

## License

Apache-2.0, see [LICENSE](LICENSE).
Copyright 2026 Project-Stateful-Zenith Contributors.
