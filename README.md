# nom-teltonika, easily parse the teltonika protocol

[![crates.io version](https://img.shields.io/crates/v/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![crates.io downloads](https://img.shields.io/crates/dr/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![docs.rs](https://img.shields.io/docsrs/nom-teltonika?style=flat-square)](https://docs.rs/nom-teltonika)
[![CI](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)

Decode and encode Teltonika TCP and UDP packets in Rust with a dependency-free core.

## Installation

```toml
[dependencies]
nom-teltonika = "0.2"
```

The crate requires Rust 1.85 or newer.
The default build enables no Cargo features and uses no third-party runtime dependencies.

## Capabilities

- Decode the length-prefixed TCP IMEI handshake.
- Decode TCP AVL data using Codec 8, Codec 8 Extended, or Codec 16.
- Decode Codec 12 commands, responses, and device-specific message types.
- Decode UDP AVL packets while preserving their IMEI and packet identifiers.
- Encode IMEI decisions, TCP AVL ACK/NACK responses, correlated UDP ACKs, and Codec 12 command batches.
- Read and write synchronous TCP streams and UDP sockets.
- Return owned protocol values with explicit framing, validation, and transport errors.

## Cargo features

| Feature | Adds |
| --- | --- |
| `tokio` | Async TCP stream and UDP socket methods. |
| `serde` | Serialization of wire models and validated deserialization of `Imei`, `TcpLimits`, and `UdpLimits`. |
| `chrono` | Conversion between `AvlTimestamp` and `DateTime<Utc>`. |
| `tracing` | Framing events without IMEI, coordinates, commands, or payloads. |

Enable only the integrations you need:

```toml
[dependencies]
nom-teltonika = { version = "0.2", features = ["tokio", "serde"] }
```

## Examples

### Decode a packet

TCP decoders accept a byte slice and return an owned value with the number of consumed bytes.

```rust
use nom_teltonika::{
    encoder::encode_codec12_command,
    decoder::decode_tcp_frame,
    protocol::Frame,
};

let bytes = encode_codec12_command(b"getinfo")?;
let decoded = decode_tcp_frame(&bytes)?;

let Frame::Codec12(packet) = decoded.value else {
    panic!("expected Codec 12");
};

assert_eq!(packet.message().payload_as_str(0)?.unwrap(), "getinfo");
assert_eq!(decoded.consumed, bytes.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `decoder::decode_imei` for the TCP handshake. `decode_udp_datagram` requires
exactly one complete datagram and returns `UdpDatagram` directly.

### Handle a TCP connection

Read the IMEI handshake before passing the connection to `TeltonikaTcpStream`.
The stream never acknowledges packets automatically.

```no_run
use std::{io::Read, net::TcpListener};
use nom_teltonika::{
    decoder::decode_imei,
    protocol::Frame,
    stream::TeltonikaTcpStream,
};

let listener = TcpListener::bind("0.0.0.0:5000")?;
let (mut socket, _) = listener.accept()?;

let mut handshake = [0_u8; 17];
socket.read_exact(&mut handshake)?;
let imei = decode_imei(&handshake)?.value;

let accepted = imei.as_str() == "356307042441013";
let mut stream = TeltonikaTcpStream::new(socket);
stream.write_imei_approval(accepted)?;

if accepted {
    match stream.read_frame()? {
        Frame::Avl(packet) => {
            // Persist the records before acknowledging them.
            stream.write_avl_ack(packet.records().len() as u32)?;
        }
        Frame::Codec12(packet) => {
            println!("{:?}", packet.message().payloads());
        }
        _ => {}
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Keep the connection open to send Codec 12 commands.
Do not read directly from the underlying transport after wrapping it because the stream may buffer bytes from the next frame.

### Receive UDP packets

Send each acknowledgment to the source address and reuse the packet identifiers returned by the device.

```no_run
use std::net::UdpSocket;
use nom_teltonika::udp::TeltonikaUdpSocket;

let socket = UdpSocket::bind("0.0.0.0:5001")?;
let mut socket = TeltonikaUdpSocket::new(socket);

let (datagram, peer) = socket.recv_datagram()?;
socket.send_ack_to(
    peer,
    datagram.channel_packet_id(),
    datagram.avl_packet_id(),
    datagram.packet().records().len() as u8,
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

More executable examples are available in [`examples/`](examples/).

## Protocol notes

### Library assumptions

- Decoding validates wire structure; it does not imply that your application accepted or persisted the records.
- Stream and socket wrappers never acknowledge packets automatically.
- Codec 12 payloads are arbitrary bytes; call `payload_as_str` only when you expect UTF-8.
- GPS coordinates retain their exact signed wire values, including anomalous values.
- AVL IO identifiers, units, sizes, and multipliers depend on the device model and firmware; the crate does not embed one global mapping.
- Codec 12 commands require an open GPRS session.

### Framing and transport

- Wire integers are big-endian.
- CRC-16/IBM covers the codec ID through the second record or command count.
- A TCP session starts with the length-prefixed IMEI handshake.
- `TeltonikaTcpStream` may read ahead and retain bytes belonging to the next frame.
- UDP acknowledgments must reuse both packet identifiers and be sent to the source peer.

The `encoder` module produces IMEI decisions, TCP AVL ACK/NACK responses,
correlated UDP ACKs, and complete Codec 12 command frames.
Codec 12 encoders return `EncodeError` for empty, oversized, or unrepresentable batches.
Stream ACK methods return `io::Result<()>`, while Codec 12 command methods return `CommandWriteError`.

### Errors and limits

| Error | Action |
| --- | --- |
| `DecodeError::Incomplete { needed }` | Keep the entire buffer and read at least `needed` more bytes. |
| `DecodeError::Rejected` | Discard the reported `consumed` bytes. You may send a NACK. |
| `DecodeError::Fatal` | Stop using the connection unless you have a resynchronization strategy. |

`TeltonikaTcpStream` returns `StreamReadError::Closed` at a frame boundary and
`StreamReadError::Truncated { buffered, needed }` when the connection closes
during a frame. UDP decoding uses `UdpDecodeError`; a failure invalidates only
the current datagram.

The default maximum complete wire sizes are 1280 bytes for AVL TCP frames,
64 KiB for Codec 12 frames, and 2048 bytes for UDP datagrams.
The Codec 12 and UDP defaults are local safety policies rather than Teltonika wire limits.
Configure lower model-specific limits when required.

### References

See the [0.2 migration guide](docs/migration-0.2.md) when upgrading from 0.1.
Protocol details are available in Teltonika's official
[Data Sending Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
documentation.

Limit defaults and framing rules were checked against Teltonika's
[Data Sending Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
and [Codec](https://wiki.teltonika-gps.com/view/Codec) documentation.
