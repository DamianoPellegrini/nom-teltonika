# nom-teltonika, easily parse the teltonika protocol

[![crates.io version](https://img.shields.io/crates/v/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![crates.io recent downloads](https://img.shields.io/crates/dr/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![docs.rs build](https://img.shields.io/docsrs/nom-teltonika?style=flat-square)](https://docs.rs/nom-teltonika)

[![build status](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/test_and_release.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/test_and_release.yml)
[![clippy](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/clippy.yml/badge.svg)](https://github.com/DamianoPellegrini/nom-teltonika/actions/workflows/clippy.yml)

[![license badge](https://img.shields.io/crates/l/nom-teltonika?style=flat-square)](https://crates.io/crates/nom-teltonika)
[![repo stars](https://img.shields.io/github/stars/DamianoPellegrini/nom-teltonika?style=social)](https://github.com/DamianoPellegrini/nom-teltonika)

This package makes use of the [nom crate](https://docs.rs/nom) to parse the binary packets.

## Capabilities

- Parsing:
  - Codec 8, 8-Extended and 16 (aka TCP/UDP Protocol).
  - Codec 12 command responses.
  - It **DOES NOT** currently parse Codec 13 and 14, it **MAY** does so in the future.

- It fails parsing if any of the following checks fail:
  - Preamble **MUST BE** 0x00000000
  - CRCs **DOES NOT** match
  - Record Counts **DOES NOT** match
  - UDP Un-usable byte **MUST BE** 0x01
  - Command response type byte **MUST BE** 0x06

- It allows for sending commands to a device using Codec 12 **ONLY**.

## Features

A TeltonikaStream wrapper is provided to easily parse the incoming packets.

The following opt-in features are available:

- serde (ser/deser-ialization using the [serde crate](https://docs.rs/serde))
- tokio (async framework using the [tokio crate](https://docs.rs/tokio))

```toml
[dependencies]
nom-teltonika = { version = "*", features = ["serde", "tokio"] }
```

## Examples

### Imei parsing

```rust
let imei_buffer = [0x00, 0x0F, 0x33, 0x35,
                   0x36, 0x33, 0x30, 0x37,
                   0x30, 0x34, 0x32, 0x34,
                   0x34, 0x31, 0x30, 0x31,
                   0x33
                   ];

let (rest, imei) = nom_teltonika::parser::imei(&imei_buffer).unwrap();

assert_eq!(rest, &[]);
assert_eq!(imei, String::from("356307042441013"));
```

### Tcp Frame parsing

```rust
let buffer = [0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x36,
              0x08, 0x01, 0x00, 0x00,
              0x01, 0x6B, 0x40, 0xD8,
              0xEA, 0x30, 0x01, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x01, 0x05,
              0x02, 0x15, 0x03, 0x01,
              0x01, 0x01, 0x42, 0x5E,
              0x0F, 0x01, 0xF1, 0x00,
              0x00, 0x60, 0x1A, 0x01,
              0x4E, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x01, 0x00, 0x00,
              0xC7, 0xCF
              ];

let (rest, frame) = nom_teltonika::parser::tcp_frame(&buffer).unwrap();

assert_eq!(rest, &[]);
println!("{frame:#?}");
```

#### Or by using the TeltonikaStream wrapper

```rust
let mut file = std::fs::File::open("tests/test.bin").unwrap();

let mut stream = nom_teltonika::TeltonikaStream::new(file);

let frame = stream.read_frame().unwrap();

println!("{frame:#?}");
```

*Further examples can be found in the examples folder.*
