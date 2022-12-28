# argo-rs

Teltonika parser using nom written in Rust.

The name comes from the greek giant `Αργος Πανοπτης` which translates to `Argo the all-seeing`.

This package makes use of the [nom](https://crates.io/crates/nom) crate to parse the binary packets.

## Features

- [x] IMEI parsing
- [x] Packet parsing
- [ ] Error handling
- [ ] UDP Packet parsing
- [ ] GPRS Protocol parsing

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
argo = "0.0.1"
```

and then:

```rust
use argo::{imei, packet};

// Parse an IMEI from a byte slice, consists of length and IMEI
let (_, imei) = imei(&buffer).unwrap();

// Parse a packet from a byte slice
let (_, packet) = packet(&buffer).unwrap();
```
