The KMB/KMP protocol of PQplus and KMB power quality meters (UMD-98 and the
SMP family), without I/O.

`kmb` builds the frames to send and decodes the frames received. It opens
no sockets and reads no clock, so it works with any transport and every
step can be tested byte for byte. For a ready client on Tokio, use
[`kmb-tokio`](https://github.com/Project-Stateful-Zenith/zenith-kmb/tree/main/kmb-tokio).

| Module | Contents |
| --- | --- |
| [`frame`] | frames: encode, decode, and [`FrameDecoder`] to reassemble them from a byte stream |
| [`command`] | the requests: identify, clock, configuration, archive reads, login, reset |
| [`reply`] | reading a reply frame as data, "no data" or a device error |
| [`identify`] | the meter's identity: serial, type, firmware, modules |
| [`rtc`], [`time`] | the meter clock and its time format (milliseconds since 2000) |
| [`uni`] | universal configuration: the self-description meters send, and values decoded with it |
| [`archive`] | archive layouts, ring buffer positions and record checks |
| [`envelope`], [`pin`] | the encrypted link and the login PIN |
| [`crc`] | the frame checksum |

## Example

Build the request that identifies the meter at bus address 1, then read
the meter's answer as it arrives from a socket, in two pieces:

```rust
use kmb::{Frame, FrameDecoder, Identify, Reply, command};

let request = command::identify(1).encode()?;
assert_eq!(request.first(), Some(&1));

let identity = [
    0x30, 0x39, 0x94, 0x00, 0x00, 0x30, 0x18, 0xD1, 0x00, 0x02, 0x00, 0xA0, 0x01, 0x30,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00,
];
let received = Frame::new(1, 1, identity).encode()?;
let (first, second) = received.split_at(5);

let mut decoder = FrameDecoder::new();
decoder.push(first);
assert!(decoder.next_frame().is_none());
decoder.push(second);
let frame = decoder.next_frame().ok_or("no frame")??;

let Ok(Reply::Data(payload)) = frame.reply() else {
    return Err("not a data reply".into());
};
let meter = Identify::decode(payload)?;
assert_eq!(meter.device_no, 12345);
assert_eq!(meter.firmware_version(), "0.9.0.6353");
assert!(meter.is_universal());
Ok::<(), Box<dyn std::error::Error>>(())
```
