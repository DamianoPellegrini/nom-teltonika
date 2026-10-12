# nom-teltonika

[![crates.io version](https://img.shields.io/crates/v/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![crates.io downloads](https://img.shields.io/crates/dr/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![docs.rs](https://img.shields.io/docsrs/nom-teltonika?style=flat-square)](https://docs.rs/nom-teltonika)
[![CI](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)

Teltonika GPS trackers report positions and sensor readings to a server over
TCP or UDP, and take text commands back. This crate reads and writes that
protocol in Rust: the IMEI handshake, AVL data in Codec 8, 8 Extended, and
16, Codec 12 commands and responses, and the acknowledgments a server sends.

Decoding doesn't copy: you get a validated view over your own buffer, and
copy it into an owned value only if you need to keep it. The core has no
dependencies and works without the standard library. Optional wrappers
handle a TCP connection or a UDP socket for you, blocking or with Tokio.

The name is historical: the crate started on [nom](https://docs.rs/nom) and
no longer depends on it.

## Installation

```toml
[dependencies]
nom-teltonika = "0.3"
```

Rust 1.87 or newer. Coming from 0.1 or 0.2.0? Read the
[migration guide](docs/migration-0.3.md).

## Example

A server that accepts every device and acknowledges what it receives:

```rust no_run
# #[cfg(feature = "std")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::net::TcpListener;

use nom_teltonika::protocol::FrameView;
use nom_teltonika::tcp::{ReadFrameError, TeltonikaTcpStream};

let listener = TcpListener::bind("0.0.0.0:5000")?;
let (socket, _) = listener.accept()?;
let mut stream = TeltonikaTcpStream::new(socket);

let imei = stream.read_imei()?.evaluate();
stream.write_imei_approval(true)?;

loop {
    match stream.read_frame() {
        Ok(FrameView::Avl(packet)) => {
            for record in packet.records() {
                let gps = record.gps();
                println!("{imei}: {}, {}", gps.latitude_degrees(), gps.longitude_degrees());
            }
            // Acknowledge once the records are stored. The view borrows the
            // stream, so count before writing.
            let accepted = packet.records().len() as u32;
            stream.write_avl_ack(accepted)?;
        }
        Ok(_) => {}
        Err(ReadFrameError::InvalidFrame(_)) => stream.write_avl_nack()?,
        Err(ReadFrameError::Closed) => break,
        Err(error) => return Err(error.into()),
    }
}
# Ok(())
# }
# #[cfg(not(feature = "std"))]
# fn main() {}
```

The [`examples`](examples/) directory has blocking, Tokio, and UDP servers.
The [documentation](https://docs.rs/nom-teltonika) explains decoding from
your own buffers, acknowledgments, limits, and where the crate reads the
protocol in a way worth knowing.

## Features

`std` is on by default. Turn default features off for a `no_std` build.

- `std`: the TCP stream and UDP socket wrappers.
- `alloc`: owned values and encoders that return a `Vec`.
- `tokio`: `async` versions of the wrappers.
- `serde`: serialization of decoded values.
- `chrono`: timestamp conversions to `chrono`.
- `tracing`: events from the wrappers.

## Performance

Measured on one thread of an Apple M1 Pro with Rust 1.98, over 64 MiB of
frames. Numbers depend on the machine.

`cargo bench --bench decoder -- bulk`, on frames of every codec:

| Operation | Throughput | Records per second |
| --- | --- | --- |
| Decode | 1.5 GiB/s | 18.0 million |
| Decode and read every record and IO element | 780 MiB/s | 8.9 million |
| Decode and copy into an owned `Frame` | 523 MiB/s | 5.9 million |
| Read through `TeltonikaTcpStream` | 1.5 GiB/s | 17.4 million |
| Decode UDP datagrams, which have no CRC | 6.0 GiB/s | |
| Encode | 1.0 GiB/s | |

### Compared with 0.1.6 and other parsers

`cargo bench -p teltonika-comparison`, on Codec 8 frames of 1 to 4 records.
The other two crates decode only those.

| Parser | Output | Throughput | Records per second | Against 0.1.6 |
| --- | --- | --- | --- | --- |
| nom-teltonika | Views, records counted | 2.0 GiB/s | 18.9 million | 13.4× |
| nom-teltonika | Views, every value read | 736 MiB/s | 6.8 million | 4.8× |
| nom-teltonika | Owned | 386 MiB/s | 3.6 million | 2.5× |
| nom-teltonika 0.1.6 | Owned | 153 MiB/s | 1.4 million | 1× |
| teltonika-rs 0.1.1 | Owned | 246 MiB/s | 2.3 million | 1.6× |
| teltonika-avl-protocol 0.1.0 | Fixed capacity | 113 MiB/s | 1.0 million | 0.7× |

teltonika-rs prints a message when the CRC is wrong and returns the frame
anyway. The other parsers return an error.

On frames of every codec:

| Parser | Output | Throughput | Records per second | Against 0.1.6 |
| --- | --- | --- | --- | --- |
| nom-teltonika | Views, records counted | 1.7 GiB/s | 14.0 million | 11.3× |
| nom-teltonika | Views, every value read | 762 MiB/s | 6.0 million | 4.9× |
| nom-teltonika | Owned | 475 MiB/s | 3.8 million | 3.0× |
| nom-teltonika 0.1.6 | Owned | 156 MiB/s | 1.2 million | 1× |

`cargo run --release -p teltonika-comparison` prints these tables.

## Testing a server

`tools/simulator` in this repository simulates devices: it connects over
TCP or UDP, sends realistic traffic, answers commands, can inject faults,
and reports how the server answered. It is not published.

```sh
cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5000 --devices 100
```

[docs/simulator.md](docs/simulator.md) has commands to run it against the
example servers.

## Protocol

The protocol follows Teltonika's
[Data Sending Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
and [Codec](https://wiki.teltonika-gps.com/view/Codec) documentation.

## License

[MIT](./LICENSE)
