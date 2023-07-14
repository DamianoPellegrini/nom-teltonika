# nom-teltonika, easily parse the teltonika protocol

![crates.io version](https://img.shields.io/crates/v/nom-teltonika?style=flat-square)
![crates.io recent downloads](https://img.shields.io/crates/dr/nom-teltonika?style=flat-square)
![docs.rs build](https://img.shields.io/docsrs/nom-teltonika?style=flat-square)

![build status](https://img.shields.io/github/actions/workflow/status/DamianoPellegrini/nom-teltonika/test_and_release.yml?style=flat-square)
![ci checks](https://img.shields.io/github/checks-status/DamianoPellegrini/nom-teltonika/main?style=flat-square)

![license badge](https://img.shields.io/crates/l/nom-teltonika?style=flat-square)
![repo stars](https://img.shields.io/github/stars/DamianoPellegrini/nom-teltonika?style=social)

This package makes use of the [nom crate](https://docs.rs/nom) to parse the binary packets.

## Capabilities

It parses Codec 8, 8-Extended and 16 (aka TCP/UDP Protocol).

It **DOES NOT** currently parse Codec 12, 13 and 14 (aka GPRS Protocol), it **MAY** does so in the future.

It fails parsing if any of the following checks fail:

- Preamble **MUST BE** 0x00000000
- CRCs **DOES NOT** match
- Record Counts **DOES NOT** match
- UDP Un-usable byte **MUST BE** 0x01

## Features

A TcpStream wrapper is provided to easily parse the incoming packets.

The following opt-in features are available:

- serde (ser/deser-ialization using the [serde crate](https://docs.rs/serde))

```toml
[dependencies]
nom-teltonika = { version = "*", features = ["serde"] }
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

### Tcp Packet parsing

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

let (rest, packet) = nom_teltonika::parser::tcp_packet(&buffer).unwrap();

assert_eq!(rest, &[]);
println!("{packet:#?}");
```
