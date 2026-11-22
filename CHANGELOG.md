# Changelog

All notable changes to `kmb` and `kmb-tokio`. Both crates share one
version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Documentation

- docs/protocol.md records the envelope as one real meter showed it: PKCS#7
  padding and the MAC input match the crate, a refused envelope comes back
  in cleartext as command 239 with code 10, and `ENC_psk` reads as zeros
  while a written zero key leaves the stored key in place.
- docs/protocol.md no longer marks as tested what no test pins: validity
  dates and key usage of a pinned certificate are now "implemented", and the
  envelope one-frame rule reads the same in both places. README says the
  tests use constructed frames, not recorded ones.

### Fixed

- kmb-tokio: a meter that cannot open an envelope answers in cleartext with
  command 239 (111 | 0x80) and code 10. The client now reads that as the
  error reply to the request and returns `Error::KeyRejected` instead of
  `Error::Envelope(NotEnvelope(239))`.
- kmb-tokio: an archive reply frame that carries more records than were
  requested is an error. Before, every record was kept, so a meter could
  return far more than `max_records` and the 1.2.0 memory bound did not
  hold.
- kmb-tokio: after `Error::Timeout` the late reply could still arrive and be
  taken as the answer to the next request, which put archive records under
  the wrong slots. A client whose request timed out now refuses further
  requests with `Error::Precondition` until it is reconnected; after a short
  multi-frame reply it waits for the line to go quiet before the next
  request, and the description page retry does the same.
- kmb-tokio: `Client::exchange` no longer panics on a huge reply count.

### Documentation

- docs/protocol.md records what one real meter showed: the slot at
  `max_rec + cur_rec` of a wrapped ring is the erased next write position,
  so skipping it loses nothing; meter time is UTC; the 8-byte archive
  request is answered; a group write and commit change only that field and
  the change counter. A new evidence level, observed, marks these.

## [1.2.0] - 2026-11-22

### `kmb`

- `envelope::random` reads the random of an envelope frame.
- `Geometry::iter_batches` plans archive batches lazily; `batches`
  collects it.
- `Frame::reply_to` reads a reply knowing the request's command.
- Fix: a reply to a request with an opcode of 128 or more, such as
  `MTU_PROBE` (146), is no longer read as an error reply by
  `Frame::reply_to`; only `request | 0x80` to a request below 128 is one.
- Fix: identify name and archive definition strings (`kmb_string`) are
  decoded as CP1252, like universal strings, instead of as UTF-8.

### `kmb-tokio`

- Security: once the envelope is in use, a cleartext reply other than an
  error is refused instead of being returned unauthenticated (#2).
- Security: `Client::set_require_encryption` makes a meter that answers in
  cleartext an error before any frame carrying the PIN is sent (#5).
- Security: a reply must answer the command that was sent, and an envelope
  whose random was already seen in the session is refused (#7).
- Security: an archive download refuses a ring of more than
  `MAX_RECORDS` records (`Client::set_max_records`) and plans its batches
  lazily, so a meter can no longer make the client allocate gigabytes (#3).
- Security: each reply frame has to arrive within `REPLY_TIMEOUT`
  (`Client::set_reply_timeout`), so a peer that trickles bytes can no
  longer stall a reply indefinitely (#4).
- Security: description paging that does not advance is an error instead
  of an endless loop (#11).
- Security: `tls::Verifier::expecting_common_name` and
  `tls::connect_tls_with` bind a root-trusted TLS connection to one meter's
  certificate common name, so another certificate from the same CA is
  refused (#8). `tls::subject` and `tls::common_name` read a certificate's
  subject.
- Security: `Client::set_refuse_cleartext_pin` makes requests that carry
  the PIN fail before they are sent unless the envelope or a secure
  transport protects them; `connect_tls` marks its transport secure, and
  `Client::set_secure_transport` does so for other transports (#6).
- Fix: bytes already waiting on the stream, such as a late reply after a
  timeout or the tail of a discarded frame, are discarded before each
  request instead of being read as its reply.
- Fix: a reply to a request with an opcode of 128 or more is no longer
  taken for an error reply, and the envelope policy treats it as data.
- Fix: when a multi-frame archive reply stops short, the frames already
  received are returned instead of a timeout; a timeout on the first frame
  is still `Error::Timeout`.

### Examples

- Security: `probe` takes the password and PSK from `KMB_PASSWORD` /
  `KMB_PSK` or from `--password-file` / `--psk-file`; `--password` and
  `--psk` are refused, so secrets stay out of process lists and shell
  history (#9).
- Security: `probe` prints the names and units the meter sends with control
  characters escaped, so a meter cannot drive the terminal (#10).

### Dependencies

- Security: rustls 0.23.46, rustls-webpki 0.103.17, ctutils 0.4.8 and
  tokio 1.54.1, past RUSTSEC-2026-0346 to 0349, 0382, 0385 and 0386.
  kmb-tokio asks for rustls-webpki 0.103.17 and tokio 1.54 at least (#1).

### Documentation

- docs/protocol.md describes the wire protocol as the crate implements it:
  frames, replies, PIN, envelope, TLS, commands, universal configuration and
  archives, each fact marked tested, implemented or assumed, with the known
  unknowns. The READMEs now claim support for universal-configuration SMP
  meters only; other families are identified but not supported.
- The README explains how a sniffed PIN gives the PIN of every meter with
  the same credentials, and recommends per-meter credentials (#6).

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

[1.2.0]: https://github.com/Project-Stateful-Zenith/zenith-kmb/releases/tag/v1.2.0
[1.1.4]: https://github.com/Project-Stateful-Zenith/zenith-kmb/releases/tag/v1.1.4
[1.1.3]: https://github.com/Project-Stateful-Zenith/zenith-kmb/releases/tag/v1.1.3
