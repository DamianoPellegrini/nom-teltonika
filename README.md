# nom-teltonika

[![crates.io version](https://img.shields.io/crates/v/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![crates.io downloads](https://img.shields.io/crates/dr/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![docs.rs](https://img.shields.io/docsrs/nom-teltonika?style=flat-square)](https://docs.rs/nom-teltonika)
[![CI](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![GitHub stars](https://img.shields.io/github/stars/DamianoPellegrini/nom-teltonika?style=social)](https://github.com/DamianoPellegrini/nom-teltonika)

`nom-teltonika` parses and encodes Teltonika TCP and UDP wire protocols. The
crate name is historical: version 0.2 uses a dependency-free, safe Rust core and
does not depend on `nom`.

The library supports AVL Codec 8, Codec 8 Extended, Codec 16, and Codec 12
command/response packets. It constructs owned frames in one pass from
caller-owned byte slices, provides explicit acknowledgments, and includes a
multi-peer UDP socket wrapper.

Choose this crate when you need protocol validation and transport framing while
retaining control over connection lifecycle, persistence, retries, and
acknowledgment policy. It is not a device server, IO-ID catalogue, database
adapter, or background ingestion service.

## Quick start

Add the dependency without default features:

```toml
[dependencies]
nom-teltonika = "0.2"
```

Parse one TCP frame. `consumed` lets you retain a concatenated or partial next
frame in your own buffer.

```rust
use nom_teltonika::{
    encode::encode_codec12_command,
    parser::parse_tcp_frame,
    protocol::Frame,
};

let bytes = encode_codec12_command(b"getinfo");
let parsed = parse_tcp_frame(&bytes).unwrap();

let Frame::Codec12(packet) = parsed.value else {
    panic!("expected Codec 12 data");
};
assert_eq!(packet.message().payload_as_str(0).unwrap().unwrap(), "getinfo");
assert_eq!(parsed.consumed, bytes.len());
```

The public API is grouped by responsibility: parsers and parse errors live under
`parser`, owned wire models under `protocol`, encoders under `encode`, stream
handling under `stream`, and UDP socket handling under `udp`.

| If you need to… | Start with… |
| --- | --- |
| parse bytes managed by your application | `parser::parse_tcp_frame` or `parse_udp_datagram` |
| read frames from a blocking TCP stream | `stream::TeltonikaStream::read_frame` |
| use Tokio TCP or UDP | the `tokio` feature and methods ending in `_async` |
| serve multiple UDP devices on one socket | `udp::TeltonikaUdpSocket` |
| encode a response without a wrapper | the free functions in `encode` |
| inspect decoded records and payloads | the owned values in `protocol` |

Items are intentionally not re-exported from the crate root:

```compile_fail
use nom_teltonika::{Frame, parse_tcp_frame};
```

```rust
use nom_teltonika::{parser::parse_tcp_frame, protocol::Frame};

let _parser = parse_tcp_frame;
let _frame_size = std::mem::size_of::<Frame>();
```

Parse the TCP IMEI handshake independently:

```rust
use nom_teltonika::parser::parse_imei;

let handshake = b"\x00\x0f356307042441013";
let parsed = parse_imei(handshake).unwrap();
assert_eq!(parsed.value.as_str(), "356307042441013");
assert_eq!(parsed.consumed, handshake.len());
```

Use `TeltonikaStream` when the result must own all variable data and outlive the
receive buffer:

```rust
use std::io::Cursor;
use nom_teltonika::{
    encode::encode_codec12_command,
    protocol::Frame,
    stream::TeltonikaStream,
};

let bytes = encode_codec12_command(b"getinfo");
let mut stream = TeltonikaStream::new(Cursor::new(bytes));
let Frame::Codec12(packet) = stream.read_frame().unwrap() else {
    panic!("expected Codec 12");
};
assert_eq!(packet.message().payload_as_str(0).unwrap().unwrap(), "getinfo");
```

## Run a TCP device session

A Teltonika TCP session starts with the IMEI handshake, not an AVL frame. Read
and validate it first, send the one-byte decision, and then hand the same
connection to `TeltonikaStream`. Keep the connection open when you need to send
Codec 12 commands.

```no_run
use std::{io::Read, net::TcpListener};
use nom_teltonika::{
    parser::parse_imei,
    protocol::Frame,
    stream::TeltonikaStream,
};

let listener = TcpListener::bind("127.0.0.1:5000")?;
let (mut socket, _peer) = listener.accept()?;

// The protocol fixes the IMEI body at 15 ASCII digits.
let mut handshake = [0_u8; 17];
socket.read_exact(&mut handshake)?;
let imei = parse_imei(&handshake)?.value;

let authorized = imei.as_str() == "356307042441013";
let mut stream = TeltonikaStream::new(socket);
stream.write_imei_approval(authorized)?;
if !authorized {
    return Ok(());
}

loop {
    match stream.read_frame()? {
        Frame::Avl(packet) => {
            // Persist or enqueue before acknowledging if that is your durability boundary.
            let accepted = u32::try_from(packet.records().len()).unwrap();
            stream.write_avl_ack(accepted)?;
        }
        Frame::Codec12(packet) => {
            for payload in packet.message().payloads() {
                println!("Codec 12 payload: {payload:?}");
            }
        }
        _ => {
            // `Frame` is non-exhaustive so future codec families remain compatible.
        }
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`TeltonikaStream` may read ahead into later frames. Do not read directly from
its underlying transport, and do not call `into_inner` until you can discard any
buffered unread bytes. Writing transport configuration through `get_mut` is
safe; bypassing the wrapper for reads is not.

## Manage your own receive buffer

The slice parser never retains state and parses at most one frame. Keep every
byte on `Incomplete`, remove `consumed` bytes on success or `Rejected`, and stop
using the connection on `Fatal` unless you have a protocol-specific
resynchronization rule.

```rust
use nom_teltonika::{
    parser::{parse_tcp_frame, ParseError},
    protocol::Frame,
};

fn take_frame(buffer: &mut Vec<u8>) -> Result<Option<Frame>, ParseError> {
    match parse_tcp_frame(buffer) {
        Ok(parsed) => {
            buffer.drain(..parsed.consumed);
            Ok(Some(parsed.value))
        }
        Err(ParseError::Incomplete { .. }) => Ok(None),
        Err(error @ ParseError::Rejected { consumed, .. }) => {
            buffer.drain(..consumed);
            Err(error)
        }
        // Includes Fatal and any failure variants added in a compatible release.
        Err(error) => Err(error),
    }
}

let mut buffer = Vec::new();
assert!(take_frame(&mut buffer).unwrap().is_none());
```

`Limits` count complete wire bytes. Lower them only when your device fleet has a
known smaller maximum; overly small limits reject valid packets. Raise them only
with an explicit per-connection memory budget.

## Receive UDP safely

UDP acknowledgments must echo both packet identifiers and go back to the source
address returned by the receive operation. `TeltonikaUdpSocket` keeps those
requirements visible at the call site and detects datagrams larger than its
configured buffer.

```no_run
use std::net::UdpSocket;
use nom_teltonika::udp::TeltonikaUdpSocket;

let socket = UdpSocket::bind("0.0.0.0:5001")?;
let mut socket = TeltonikaUdpSocket::new(socket);

let (datagram, peer) = socket.recv_datagram()?;
let accepted = u8::try_from(datagram.packet().records().len()).unwrap();
socket.send_ack_to(
    peer,
    datagram.channel_packet_id(),
    datagram.avl_packet_id(),
    accepted,
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Error policy

`ParseError::Incomplete` never consumes input. `ParseError::Rejected` identifies
a complete, safely delimited invalid frame and reports how many bytes the caller
may consume. `ParseError::Fatal` reports framing that cannot be safely trusted,
including invalid preambles, arithmetic overflow, and declared lengths above the
configured limit.

The stream consumes a rejected frame before returning its error. It returns
`StreamError::Closed` for EOF at a frame boundary and `StreamError::Truncated`
for EOF with partial buffered data. No read path sends an automatic ACK.

## Encoders

The `encode` module exports fixed-size encoders for IMEI approval, TCP AVL
ACK/NACK, and correlated UDP ACK, plus Codec 12 single/batch encoders. Variable
encoders accept bytes, so non-UTF-8 commands are preserved. Stream writes flush
automatically.

Codec 12 commands require an open GPRS session. Keep application connection
policy, retries, and ACK timing outside this crate.

Commands and Codec 12 responses are byte payloads. Use `payload_as_str` only as
a checked convenience: `None` means the index is absent, while `Some(Err(_))`
means the payload exists but is not UTF-8.

## Optional features

No feature is enabled by default.

- `tokio`: async stream methods and `tokio::net::UdpSocket` integration.
- `serde`: serialization of wire models plus validated deserialization for
  `Imei` and `Limits`. Parsed wire models intentionally do not implement
  `Deserialize`, because JSON input has not passed wire validation.
- `chrono`: checked conversion from `AvlTimestamp` to `DateTime<Utc>`.
- `tracing`: privacy-safe `trace` and `debug` events containing framing metadata
  only. Events omit IMEIs, coordinates, commands, and payloads.

See [the 0.2 migration guide](docs/migration-0.2.md) for the complete breaking
rename and behavior changes.

## Model assumptions

- Integers use big-endian wire order; CRC uses CRC-16/IBM over the codec ID
  through the second record or command count.
- Successful models omit preambles, lengths, CRC, and validated AVL duplicate
  counts. Encoders recompute framing rather than trusting stale metadata.
- Parsed values own variable-length data. This costs allocation but lets frames
  outlive receive buffers and move safely into worker tasks or queues.
- GPS coordinates preserve exact scaled integers. `is_position_valid` checks
  structural ranges and satellite presence; it does not establish real-world
  accuracy.
- AVL IO IDs are model- and firmware-specific. The crate preserves identifiers
  and widths but does not assign universal units or meanings.
- Codec 12 duplicate-count mismatches are preserved in `CountStatus` when frame
  length still delimits the payload safely. AVL count mismatches are rejected.

## Protocol authority

Wire behavior and minimized test fixtures follow Teltonika's official
[Data Sending Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
documentation. AVL IO meanings remain model- and firmware-specific; consult the
device's parameter ID documentation rather than assuming one global mapping.
