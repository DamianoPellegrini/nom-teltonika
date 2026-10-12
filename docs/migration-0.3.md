# Migrate to 0.3

Version 0.3 replaces the `nom`-based 0.1 API and the yanked 0.2.0. This guide
starts from 0.1. Notes marked **From 0.2.0** describe what changed since the
yanked release. There are no deprecated aliases, so each rename below is a
compile error until it is applied.

## What changed at a glance

- Decoders no longer use `nom`. They are plain functions in two styles.
  `parse_*` takes `&[u8]` and returns `(rest, value)`, as the 0.1 parsers did.
  `take_*` takes a `&mut &[u8]` cursor and advances it past what it decoded. A
  UDP datagram has only `take_datagram`, because nothing remains after it.
- Decoders and streams return `*View` types. A view borrows the input and is
  fully validated. Call `evaluate` or use [`From`] to get an owned value that
  outlives the buffer, such as [`Frame`](crate::protocol::Frame) or
  [`AvlPacket`](crate::protocol::AvlPacket).
- Coordinates, timestamps, and IO values are kept as the integers the device
  sent. Conversions are methods.
- Each operation has its own error type. The error tells whether to read more,
  skip the frame, or close the connection.
- The core is `no_std`. Everything except streams and sockets works without
  `std`, and decoding works without `alloc`.

## Update `Cargo.toml`

```toml
[dependencies]
nom-teltonika = { version = "0.3", features = ["serde", "tokio"] }
```

- Rust 1.87 or newer is required.
- `std` is a default feature and enables `alloc`. With
  `default-features = false`, the decoders and views remain. Add `alloc` for
  owned values and the encoders that return a `Vec`, or `std` for streams and
  sockets.
- `chrono` is now optional. 0.1 always depended on it. Enable it to convert
  timestamps to `chrono::DateTime<Utc>`.
- `tokio` enables the `*_async` methods.
- `tracing` emits events from the stream and the socket. The events contain no
  IMEIs, coordinates, commands, or payloads.

## Find the new names

| 0.1 | 0.3 |
| --- | --- |
| `nom_teltonika::parser` | [`decoder`](crate::decoder) |
| `parser::imei` | [`parse_imei`](crate::decoder::parse_imei), [`take_imei`](crate::decoder::take_imei) |
| `parser::tcp_frame`, `AVLFrame::try_from` | [`parse_frame`](crate::decoder::parse_frame), [`take_frame`](crate::decoder::take_frame) |
| `parser::udp_datagram`, `AVLDatagram::try_from` | [`take_datagram`](crate::decoder::take_datagram) |
| `nom_teltonika::crc16` | [`crc16`](crate::crc16), unchanged |
| Types at the crate root | [`protocol`](crate::protocol) |
| `TeltonikaStream` (TCP) | [`tcp::TeltonikaTcpStream`](crate::tcp::TeltonikaTcpStream) |
| `TeltonikaStream::read_datagram` | [`udp::TeltonikaUdpSocket`](crate::udp::TeltonikaUdpSocket) |
| `TeltonikaFrame` | [`FrameView`](crate::protocol::FrameView) / [`Frame`](crate::protocol::Frame) |
| `AVLFrame` | [`AvlPacketView`](crate::protocol::AvlPacketView) / [`AvlPacket`](crate::protocol::AvlPacket) |
| `AVLDatagram` | [`DatagramView`](crate::protocol::DatagramView) / [`Datagram`](crate::protocol::Datagram) |
| `AVLRecord` | [`AvlRecordView`](crate::protocol::AvlRecordView) / [`AvlRecord`](crate::protocol::AvlRecord) |
| `AVLEventIO` | [`IoElementView`](crate::protocol::IoElementView) / [`IoElement`](crate::protocol::IoElement) |
| `AVLEventIOValue` | [`IoValueView`](crate::protocol::IoValueView) / [`IoValue`](crate::protocol::IoValue) |
| `GPRSFrame` | [`GprsPacketView`](crate::protocol::GprsPacketView) / [`GprsPacket`](crate::protocol::GprsPacket) |
| `EventGenerationCause` | [`GenerationType`](crate::protocol::GenerationType) |
| `Codec` | [`Codec`](crate::protocol::Codec), [`AvlCodec`](crate::protocol::AvlCodec), [`GprsCodec`](crate::protocol::GprsCodec) |
| IMEI as `String` | [`ImeiView`](crate::protocol::ImeiView) / [`Imei`](crate::protocol::Imei) |

**From 0.2.0:** The modules keep their names. The decoders return views instead
of owned values. These items are gone:

- `Decoded<T>`. The cursor shows what was consumed.
- `decode_*_with_limits`, `TcpLimits`, `UdpLimits`, and `LimitsError`. The
  limits are now fixed.

## Decode

A decoder takes a cursor, advances it on success, and returns a view.

```rust
use nom_teltonika::decoder::take_frame;
use nom_teltonika::protocol::FrameView;

// 0.1: let (rest, frame) = nom_teltonika::parser::tcp_frame(&buffer)?;
let buffer = hex::decode(
    "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF",
)?;
let mut input = &buffer[..];
let frame = take_frame(&mut input)?;
let rest = input; // What 0.1 returned as `rest`.
assert!(rest.is_empty());

if let FrameView::Avl(packet) = frame {
    for record in packet.records() {
        println!("{:?} {:?}", record.timestamp(), record.gps());
    }
}

// An owned copy, like the 0.1 `TeltonikaFrame`.
let owned = frame.evaluate();
# let _ = owned;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The IMEI handshake and UDP datagrams work the same way.

```rust
use nom_teltonika::decoder::{take_imei, take_datagram};

// 0.1: let (rest, imei) = nom_teltonika::parser::imei(&buffer)?;
let mut input: &[u8] = b"\x00\x0f356307042441013";
let imei = take_imei(&mut input)?;
assert_eq!(imei.as_str(), "356307042441013");

// 0.1: let (rest, datagram) = nom_teltonika::parser::udp_datagram(&buffer)?;
let buffer = hex::decode(
    "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001",
)?;
let datagram = take_datagram(&mut &buffer[..])?;
assert_eq!(datagram.imei().as_str(), "352093086403655");
# Ok::<(), Box<dyn std::error::Error>>(())
```

`take_datagram` expects exactly one whole datagram. A length that doesn't match
is an error, not a request for more bytes.

## Handle errors

0.1 returned `nom::Err`. Each operation now has its own error type.

| Operation | Error |
| --- | --- |
| [`take_imei`](crate::decoder::take_imei) | [`DecodeImeiError`](crate::decoder::DecodeImeiError) |
| [`take_frame`](crate::decoder::take_frame) | [`DecodeFrameError`](crate::decoder::DecodeFrameError) |
| [`take_datagram`](crate::decoder::take_datagram) | [`DecodeDatagramError`](crate::decoder::DecodeDatagramError) |
| [`TeltonikaTcpStream::read_imei`](crate::tcp::TeltonikaTcpStream::read_imei) | [`ReadImeiError`](crate::tcp::ReadImeiError) |
| [`TeltonikaTcpStream::read_frame`](crate::tcp::TeltonikaTcpStream::read_frame) | [`ReadFrameError`](crate::tcp::ReadFrameError) |
| [`TeltonikaTcpStream::write_commands`](crate::tcp::TeltonikaTcpStream::write_commands) | [`WriteCommandError`](crate::tcp::WriteCommandError) |
| [`TeltonikaUdpSocket::receive_datagram`](crate::udp::TeltonikaUdpSocket::receive_datagram) | [`ReceiveDatagramError`](crate::udp::ReceiveDatagramError) |
| [`encode_gprs_frame`](crate::encoder::encode_gprs_frame) | [`EncodeGprsError`](crate::encoder::EncodeGprsError) |

On a growing TCP buffer, `DecodeFrameError` tells what to do next.

```rust
use nom_teltonika::decoder::{DecodeFrameError, take_frame};

fn next(buffer: &mut Vec<u8>) -> Result<bool, DecodeFrameError> {
    let mut input = &buffer[..];
    match take_frame(&mut input) {
        // A frame, then `input` is past it.
        Ok(frame) => println!("{frame:?}"),
        // Nothing consumed: read at least `needed` more bytes.
        Err(DecodeFrameError::Incomplete { .. }) => return Ok(false),
        // The invalid frame is consumed: send a NACK and go on.
        Err(DecodeFrameError::InvalidFrame { reason, .. }) => println!("skipped: {reason}"),
        // Nothing consumed and the next frame can't be found: close.
        Err(error @ DecodeFrameError::InvalidHeader(_)) => return Err(error),
    }
    let consumed = buffer.len() - input.len();
    buffer.drain(..consumed);
    Ok(true)
}
# assert_eq!(next(&mut vec![0; 3]), Ok(false));
```

**From 0.2.0:** `DecodeError::{Incomplete, Rejected, Fatal}` became
`DecodeFrameError::{Incomplete, InvalidFrame, InvalidHeader}`. The reason is
now inside the variant, as a [`FrameError`](crate::decoder::FrameError) or a
[`HeaderError`](crate::decoder::HeaderError). It replaces `consumed`, `offset`,
`RejectionReason`, and `FatalReason`. Other errors were renamed:

- `UdpDecodeError` became `DecodeDatagramError`.
- `StreamReadError` became `ReadFrameError`.
- `CommandWriteError` became `WriteCommandError`.
- `UdpReceiveError` became `ReceiveDatagramError`.
- `EncodeError` became `EncodeGprsError`.

## Read record fields

0.1 records had public fields with converted values. Views and owned values
have methods instead, which return the values as sent.

| 0.1 `AVLRecord` | 0.3 `AvlRecordView` / `AvlRecord` |
| --- | --- |
| `timestamp: DateTime<Utc>` | `timestamp()` → [`AvlTimestamp`](crate::protocol::AvlTimestamp) (milliseconds) |
| `priority` | `priority()` → [`Priority`](crate::protocol::Priority) |
| `longitude`, `latitude: f64` | `gps().longitude_degrees()`, `gps().latitude_degrees()`; raw in `longitude_raw`, `latitude_raw` |
| `altitude`, `angle`, `satellites`, `speed` | `gps().altitude_meters`, `angle_degrees`, `satellites`, `speed_kph`; `gps().altitude_meters_signed()` below sea level |
| `trigger_event_id: u16` | `event_io_id()` → `Option<IoId>`, `None` for 0 |
| `generation_type: Option<EventGenerationCause>` | `generation_type()` → `Option<GenerationType>`, `None` outside Codec 16 |
| `io_events: Vec<AVLEventIO>` | `io_elements()`, an iterator on views or a slice on owned records |
| `AVLEventIOValue::Variable(Vec<u8>)` | `IoValueView::Bytes(&[u8])` / `IoValue::Bytes(Vec<u8>)` |
| `GPRSFrame::command_responses: Vec<String>` | `messages()`, each with a `kind()` and a `payload()` of bytes |

```rust
use std::time::SystemTime;

use nom_teltonika::decoder::take_frame;
use nom_teltonika::protocol::FrameView;

let buffer = hex::decode(
    "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF",
)?;
let FrameView::Avl(packet) = take_frame(&mut &buffer[..])? else {
    panic!("expected AVL data");
};
let record = packet.records().next().unwrap();

let time = SystemTime::try_from(record.timestamp())?;
let millis = u64::from(record.timestamp());
let longitude = record.gps().longitude_degrees();
let event = record.event_io_id().map(u16::from);
for element in record.io_elements() {
    println!("{:?} = {:?}", element.id(), element.value());
}
# let _ = (time, millis, longitude, event);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`EventGenerationCause::None` has no counterpart. A missing generation type is
`None`.

Codec 12 payloads are bytes, because the protocol allows any content. Use
`std::str::from_utf8` when you expect text.

**From 0.2.0:**

- `AvlRecord` and `IoElement` fields are private. Use the methods above.
- `AvlTimestamp::from_unix_millis` and `unix_millis` became [`From`] in both
  directions.
- `to_system_time` and `from_system_time` became [`TryFrom`].
- `IoId::new` and `get` became [`From`].
- `Codec12Message` and `CountStatus` are gone. Each message has its own type,
  and the second quantity is not compared with the first.
- `payload_as_str` is gone.
- `Imei` holds any ASCII text instead of exactly 15 digits.
- `Datagram::channel_packet_id()` is now `packet_id()`.

## Use the TCP stream

`TeltonikaStream` handled both TCP and UDP. TCP is now
[`TeltonikaTcpStream`](crate::tcp::TeltonikaTcpStream). Its read methods return
views that are valid until the next read. It never sends an acknowledgment on
its own.

| 0.1 `TeltonikaStream` | 0.3 `TeltonikaTcpStream` |
| --- | --- |
| `with_capacity(inner, imei, packet)` | `with_capacity(capacity, inner)` |
| `inner()`, `inner_mut()` | `get_ref()`, `get_mut()` |
| `read_imei() -> io::Result<String>` | `read_imei() -> Result<ImeiView, ReadImeiError>` |
| `read_frame() -> io::Result<TeltonikaFrame>` | `read_frame() -> Result<FrameView, ReadFrameError>` |
| `write_imei_approval()`, `write_imei_denial()` | `write_imei_approval(accepted: bool)` |
| `write_frame_ack(Some(&frame))` | `write_avl_ack(accepted_records)` |
| `write_frame_ack(None)` | `write_avl_nack()` |
| `write_command(&str)`, `write_commands(&[&str])` | same names, any `AsRef<[u8]>` |
| `*_async` | same names, with the `tokio` feature |

```rust no_run
# #[cfg(feature = "std")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::net::TcpListener;

use nom_teltonika::protocol::FrameView;
use nom_teltonika::tcp::{ReadFrameError, TeltonikaTcpStream};

let (socket, _) = TcpListener::bind("0.0.0.0:5000")?.accept()?;
let mut stream = TeltonikaTcpStream::new(socket);

let imei = stream.read_imei()?.evaluate();
stream.write_imei_approval(true)?;
loop {
    match stream.read_frame() {
        Ok(FrameView::Avl(packet)) => {
            // Acknowledge the records you stored.
            let stored = packet.records().len() as u32;
            stream.write_avl_ack(stored)?;
        }
        Ok(_) => {}
        Err(ReadFrameError::InvalidFrame(_)) => stream.write_avl_nack()?,
        Err(ReadFrameError::Closed) => break,
        Err(error) => return Err(error.into()),
    }
}
# let _ = imei;
# Ok(())
# }
# #[cfg(not(feature = "std"))]
# fn main() {}
```

A view borrows the stream. Read what you need from the view before writing the
acknowledgment, or call `evaluate` first.

**From 0.2.0:** `StreamConfig` and `StreamConfigError` are gone. Set the buffer
size with `with_capacity(capacity, inner)`. `read_frame` returns views, and the
stream now reads the IMEI handshake too.

## Use the UDP socket

0.1 read UDP datagrams through `TeltonikaStream::read_datagram`, which can't
tell devices apart. [`TeltonikaUdpSocket`](crate::udp::TeltonikaUdpSocket)
returns each datagram with its source address. An acknowledgment takes the IDs
of the datagram it answers.

```rust no_run
# #[cfg(feature = "std")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::net::UdpSocket;

use nom_teltonika::udp::TeltonikaUdpSocket;

let mut socket = TeltonikaUdpSocket::new(UdpSocket::bind("0.0.0.0:5001")?);
let (datagram, peer) = socket.receive_datagram()?;
let ids = datagram.ids();
let stored = datagram.packet().records().len() as u8;
// 0.1: stream.write_datagram_ack(Some(&datagram))?;
socket.send_ack_to(peer, ids, stored)?;
# Ok(())
# }
# #[cfg(not(feature = "std"))]
# fn main() {}
```

**From 0.2.0:** `recv_datagram` became `receive_datagram`. `send_ack_to` takes
the [`DatagramIds`](crate::protocol::DatagramIds) instead of two integers.
`with_limits` is gone, because datagrams are never truncated.

## Encode

The [`encoder`](crate::encoder) module, new in 0.2, encodes what the stream
writes. Use it in applications that do their own I/O.

```rust
use nom_teltonika::encoder::{encode_avl_ack, encode_gprs_frame_into, encode_imei_approval};
use nom_teltonika::protocol::GprsMessageType;

assert_eq!(encode_imei_approval(true), [0x01]);
assert_eq!(encode_avl_ack(1), [0, 0, 0, 1]);

// Without `alloc`: write into your own buffer.
let mut buffer = [0; 64];
let len = encode_gprs_frame_into(GprsMessageType::Command, &["getinfo"], &mut buffer)?;
assert_eq!(len, 27);
# Ok::<(), nom_teltonika::encoder::EncodeGprsError>(())
```

**From 0.2.0:** Codec 12 encoders take a slice (`&["getinfo"]`) instead of an
iterator. `encode_udp_ack` takes the datagram's `DatagramIds`. Frames are
limited to 65,535 bytes, the longest the decoder accepts.

## Expect these behavior changes

The decoders follow Teltonika's documentation, so what they accept has changed:

- An IMEI can be any ASCII text of the declared length, over TCP and UDP. Real
  IMEIs are 15 digits. Check that yourself if you need it.
- In a UDP datagram, the byte after the packet ID is not checked. The
  documentation sets it to `0x01` only in acknowledgments. 0.1 rejected other
  values.
- Codec 12 commands (`0x05`) are decoded as well as responses (`0x06`). 0.1
  accepted only responses.
- The second Codec 12 quantity is not compared with the first. 0.1 required
  them to be equal.
- In Codec 8 Extended, "N of Total IO" must equal N1 + N2 + N4 + N8 + NX. This
  is the number of 1-, 2-, 4-, 8-byte, and variable-length elements, as devices
  send it.
- A packet without records is invalid.
- A frame with an unsupported codec, such as Codec 13, is skipped as invalid.
  It no longer ends the stream.
- Frame limits are fixed. Codec 8 and Codec 8 Extended frames can have 1280
  bytes, as Teltonika documents. Every other frame can have 65,535 bytes.
  Teltonika states no limit for those frames. A header that declares more is
  rejected before its frame is buffered, so a peer can't make a server hold
  more than that for one frame.

## Serialize

With the `serde` feature, views and owned values serialize to the same output.
The output differs from 0.1. Values are kept as sent, for example
`longitude_raw` and a `timestamp` in milliseconds. Byte payloads serialize as
bytes.

0.1 types also implemented `Deserialize`. In 0.3 only
[`Imei`](crate::protocol::Imei) does, and it validates its text. The other
values can only come from decoding.
