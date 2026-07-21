# Migrate from 0.1 to 0.2

Version 0.2 replaces the `nom`-based API and introduces operation-specific
errors. The crate keeps its historical `nom-teltonika` name, but its default
build depends only on `std`. This release intentionally provides no deprecated
aliases.

## Rename decoder and encoder APIs

Import decoding functions from `decoder` and pure encoding functions from
`encoder`.

| Earlier name | 0.2 name |
| --- | --- |
| `parser` | `decoder` |
| `encode` | `encoder` |
| `parse_*` | `decode_*` |
| `Parsed<T>` | `Decoded<T>` |
| `ParseError` | `DecodeError` |

A successful TCP decode owns its value and reports how many bytes it consumed:

```rust
// 0.1
// let (remainder, frame) = nom_teltonika::parser::tcp_frame(input)?;

// 0.2
let decoded = nom_teltonika::decoder::decode_tcp_frame(input)?;
let remainder = &input[decoded.consumed..];
let frame = decoded.value;
# let _ = (remainder, frame);
# Ok::<(), nom_teltonika::decoder::DecodeError>(())
```

`decode_udp_datagram` differs deliberately: it requires exactly one datagram
and returns `UdpDatagram` directly. A short header, declared/actual length
mismatch, configured size violation, and invalid payload have distinct
`UdpDecodeError` variants.

## Handle errors by operation

For incremental TCP input, retain the full buffer on
`DecodeError::Incomplete { needed }`, consume only `Rejected { consumed, .. }`,
and close or reset the connection after `Fatal` unless you have an external
resynchronization rule.

`TeltonikaStream::read_frame` returns `StreamReadError`. EOF during a frame
reports both `buffered` and the last exact `needed` value. IMEI decisions and
AVL ACK/NACK methods return `io::Result<()>`; Codec 12 command methods return
`CommandWriteError` because encoding can also fail.

UDP receive methods return `UdpReceiveError`. UDP acknowledgment methods return
`io::Result<()>`.

## Validate limits at construction

Replace the combined `Limits` value with `TcpLimits` and `UdpLimits`:

```rust
use nom_teltonika::decoder::{TcpLimits, UdpLimits};

let tcp = TcpLimits::new(1280, 64 * 1024)?;
let udp = UdpLimits::new(2048)?;
# let _ = (tcp, udp);
# Ok::<(), nom_teltonika::decoder::LimitsError>(())
```

The defaults are 1280 bytes for AVL TCP frames, 64 KiB for Codec 12 frames,
and 2048 bytes for UDP datagrams. Codec 12 and UDP defaults are local safety
policies. The maximum representable complete UDP datagram is 65,537 bytes.

## Encode Codec 12 commands explicitly

Codec 12 encoders now return `Result<Vec<u8>, EncodeError>` and reject empty
batches, more than 255 commands, oversized commands, and oversized frames
without panicking. The free I/O helper was removed; use the pure encoder or
`TeltonikaStream::write_commands`.

## Update protocol values

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

`Codec12Packet::counts_match()` checks both wire quantities against the number
of messages decoded from Data Size and payload lengths. `payload_as_str` now
returns `Result<Option<&str>, Utf8Error>`: `None` means only that the index is
absent.

Timestamp conversions use `TimestampError::{BeforeUnixEpoch, OutOfRange}` for
both `SystemTime` and optional Chrono integrations. `to_system_time` now returns
`Result<SystemTime, TimestampError>`.

## Enable integrations explicitly

```toml
[dependencies]
nom-teltonika = { version = "0.2", features = ["tokio", "serde"] }
```

Async reads preserve buffered progress across cancellation. Async writes are
not cancellation-safe; close the connection after a cancelled or partial
write.
