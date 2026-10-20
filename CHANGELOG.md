# Changelog

All notable changes to `kmb` and `kmb-tokio`. Both crates share one
version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.4] - 2026-10-20

### `kmb-tokio`

- Tests: the certificate issuer parser is checked against every truncation
  and single-bit flip of a real certificate.

### Documentation

- The README says the vendor PIN is an MD5-derived 32-bit value, weak on
  its own; the encrypted envelope or TLS protects the link.

## [1.1.3] - 2026-10-15

First public release.

### `kmb`

- Frames with CRC-16, encoding, decoding and reassembly from a byte stream.
- Requests for identify, clock read, set and adjust, configuration, live
  values, archive reads and resets.
- Replies as data, "no data" or device errors.
- Meter identity: serial, type, family, firmware and bootloader versions,
  modules.
- Universal configuration: reading the meter's self-description and
  decoding configuration, status and live values with it.
- Archives: layouts from the meter's description, ring buffer positions,
  record checks (length, checksum, time).
- PIN login and the encrypted envelope (AES-128-CBC, HMAC-SHA256, PSK).

### `kmb-tokio`

- Async client on Tokio over TCP: identify, clock, configuration and
  values, archive downloads by range or after a time.
- Feature `tls`: KMB over TLS, trusting a given root CA key, certificate
  pins, or both. No root key is built in.

[1.1.4]: https://github.com/Project-Stateful-Zenith/zenith-kmb/releases/tag/v1.1.4
[1.1.3]: https://github.com/Project-Stateful-Zenith/zenith-kmb/releases/tag/v1.1.3
