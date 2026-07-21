# Migrate from 0.1 to 0.2

Version 0.2 replaces the `nom`-based API. The crate keeps its historical
`nom-teltonika` name, but its default build now depends only on `std`.

## Update parser calls

Import parser functions from the crate root. A successful parse returns
`Parsed<T>` instead of a `(remainder, value)` tuple.

```rust
// 0.1
// let (remainder, frame) = nom_teltonika::parser::tcp_frame(input)?;

// 0.2
let parsed = nom_teltonika::parse_tcp_frame(input)?;
let remainder = &input[parsed.consumed..];
let frame = parsed.value;
# Ok::<(), nom_teltonika::ParseError>(())
```

`parse_tcp_frame` returns an owned `Frame`. Variable-length byte fields are copied
once into their final model, so the result never borrows `input`.

## Rename models

| 0.1 | 0.2 |
| --- | --- |
| `TeltonikaFrame` | `Frame` |
| `AVLFrame` | `AvlPacket` |
| `AVLDatagram` | `UdpDatagram` |
| `AVLRecord` | `AvlRecord` |
| `AVLEventIO` | `IoElement` |
| `AVLEventIOValue` | `IoValue` |
| `GPRSFrame` | `Codec12Packet` |
| `EventGenerationCause` | `GenerationType` |

CRC, preamble, lengths, and duplicate AVL counts no longer appear in successful
models. Coordinates remain exact signed wire integers in `GpsElement`; call
`longitude_degrees` and `latitude_degrees` for display values.

## Handle errors explicitly

Replace `nom::Err` matching with `ParseError`. Consume `consumed` only for
`Rejected`; retain the input for `Incomplete`; close or reset the transport for
`Fatal` unless your application has an externally justified resynchronization
strategy.

## Move acknowledgments into application policy

`TeltonikaStream::read_frame` no longer returns an option and never acknowledges
automatically. Write an explicit response only after the application accepts the
packet:

```rust
# use std::io::Cursor;
# use nom_teltonika::TeltonikaStream;
# let mut stream = TeltonikaStream::new(Cursor::new(Vec::<u8>::new()));
stream.write_imei_approval(true)?;
stream.write_avl_ack(2)?;
# Ok::<(), nom_teltonika::StreamError>(())
```

Use `TeltonikaUdpSocket` for UDP. Its receive methods return the source address,
and `send_ack_to` requires an explicit destination so one server socket can serve
multiple devices safely.

## Enable integrations explicitly

Chrono is no longer part of core fields. Enable only the integrations you use:

```toml
[dependencies]
nom-teltonika = { version = "0.2", features = ["tokio", "serde"] }
```

Async write methods are not cancellation-safe. Close the connection after a
cancelled or partial write. Async reads retain buffered progress and may be
called again after cancellation.
