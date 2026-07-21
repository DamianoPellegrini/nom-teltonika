# nom-teltonika

[![crates.io version](https://img.shields.io/crates/v/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![crates.io downloads](https://img.shields.io/crates/dr/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![docs.rs](https://img.shields.io/docsrs/nom-teltonika?style=flat-square)](https://docs.rs/nom-teltonika)
[![CI](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml)
[![security audit](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/audit.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/audit.yml)
[![license](https://img.shields.io/crates/l/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![GitHub stars](https://img.shields.io/github/stars/DamianoPellegrini/nom-teltonika?style=social)](https://github.com/DamianoPellegrini/nom-teltonika)

`nom-teltonika` parses and encodes Teltonika TCP and UDP wire protocols. The
crate name is historical: version 0.2 uses a dependency-free, safe Rust core and
does not depend on `nom`.

The library supports AVL Codec 8, Codec 8 Extended, Codec 16, and Codec 12
command/response packets. It constructs owned frames in one pass from
caller-owned byte slices, provides explicit acknowledgments, and includes a
multi-peer UDP socket wrapper.

## Quick start

Add the dependency without default features:

```toml
[dependencies]
nom-teltonika = "0.2"
```

Parse one TCP frame. `consumed` lets you retain a concatenated or partial next
frame in your own buffer.

```rust
use nom_teltonika::{AvlCodec, Frame, parse_tcp_frame};

let bytes = hex::decode(
    "000000000000002808010000016B40D9AD80010000000000000000000000000000000103021503010101425E100000010000F22A",
).unwrap();
let parsed = parse_tcp_frame(&bytes).unwrap();

let Frame::Avl(packet) = parsed.value else {
    panic!("expected AVL data");
};
assert_eq!(packet.codec(), AvlCodec::Codec8);
assert_eq!(packet.records().len(), 1);
assert_eq!(parsed.consumed, bytes.len());
```

Parse the TCP IMEI handshake independently:

```rust
use nom_teltonika::parse_imei;

let handshake = b"\x00\x0f356307042441013";
let parsed = parse_imei(handshake).unwrap();
assert_eq!(parsed.value.as_str(), "356307042441013");
assert_eq!(parsed.consumed, handshake.len());
```

Use `TeltonikaStream` when the result must own all variable data and outlive the
receive buffer:

```rust
use std::io::Cursor;
use nom_teltonika::{Frame, TeltonikaStream, encode_codec12_command};

let bytes = encode_codec12_command(b"getinfo");
let mut stream = TeltonikaStream::new(Cursor::new(bytes));
let Frame::Codec12(packet) = stream.read_frame().unwrap() else {
    panic!("expected Codec 12");
};
assert_eq!(packet.message().payload_as_str(0).unwrap().unwrap(), "getinfo");
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

The crate root exports fixed-size encoders for IMEI approval, TCP AVL ACK/NACK,
and correlated UDP ACK, plus Codec 12 single/batch encoders. Variable encoders
accept bytes, so non-UTF-8 commands are preserved. Stream writes flush
automatically.

Codec 12 commands require an open GPRS session. Keep application connection
policy, retries, and ACK timing outside this crate.

## Optional features

No feature is enabled by default.

- `tokio`: async stream methods and `tokio::net::UdpSocket` integration.
- `serde`: serialization of wire models plus validated deserialization for
  `Imei` and `Limits`.
- `chrono`: checked conversion from `AvlTimestamp` to `DateTime<Utc>`.
- `tracing`: privacy-safe `trace` and `debug` events containing framing metadata
  only. Events omit IMEIs, coordinates, commands, and payloads.

See [the 0.2 migration guide](docs/migration-0.2.md) for the complete breaking
rename and behavior changes.

## Protocol authority

Wire behavior and minimized test fixtures follow Teltonika's official
[Data Sending Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
documentation. AVL IO meanings remain model- and firmware-specific; consult the
device's parameter ID documentation rather than assuming one global mapping.
