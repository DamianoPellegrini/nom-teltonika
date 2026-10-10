//! Decoders and encoders for the protocols Teltonika GPS trackers speak.
//!
//! Teltonika devices send AVL data (positions and IO readings) to a server
//! over TCP or UDP, and take text commands over TCP. This crate decodes what
//! devices send, encodes what servers answer, and encodes device traffic for
//! tests and benchmarks. It has no dependencies of its own, works without the
//! standard library, and never implicitly copies a packet it doesn't have to: decoders
//! return views over your buffer.
//!
//! It is not a server. It does I/O only in the optional [`tcp`] and
//! [`udp`] wrappers, it never acknowledges data on its own, and it doesn't
//! know what an IO element means: IO IDs, sizes, and units depend on the
//! device model and firmware.
//!
//! # Choosing an entry point
//!
//! - One TCP connection per device, blocking or with Tokio: wrap it in a
//!   [`TeltonikaTcpStream`](tcp::TeltonikaTcpStream). It buffers, waits
//!   for whole frames, and writes the answers.
//! - UDP: wrap one socket in a [`TeltonikaUdpSocket`](udp::TeltonikaUdpSocket)
//!   for every device.
//! - Your own sockets, buffers, or runtime, or no `std`: call the functions
//!   in [`decoder`] on the bytes you have, and send what [`encoder`] returns.
//!
//! # A TCP session
//!
//! A device opens the connection with its IMEI and waits for one byte: `01`
//! to go on, `00` to be refused. It then sends AVL frames, and after each one
//! waits for the number of records the server accepted, as four bytes. While
//! the connection stays open, the server may send Codec 12 commands, which
//! the device answers in Codec 12 frames.
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::net::TcpListener;
//!
//! use nom_teltonika::protocol::FrameView;
//! use nom_teltonika::tcp::{ReadFrameError, TeltonikaTcpStream};
//!
//! let listener = TcpListener::bind("0.0.0.0:5000")?;
//! let (socket, _) = listener.accept()?;
//! let mut stream = TeltonikaTcpStream::new(socket);
//!
//! let imei = stream.read_imei()?.evaluate();
//! stream.write_imei_approval(true)?;
//!
//! loop {
//!     match stream.read_frame() {
//!         Ok(FrameView::Avl(packet)) => {
//!             // Store the records first: the device deletes what you
//!             // acknowledge.
//!             let accepted = packet.records().len() as u32;
//!             stream.write_avl_ack(accepted)?;
//!         }
//!         Ok(FrameView::Gprs(packet)) => {
//!             for message in packet.messages() {
//!                 println!("{imei}: {}", String::from_utf8_lossy(message.payload()));
//!             }
//!         }
//!         Ok(_) => {}
//!         // The frame is consumed: ask the device to send it again.
//!         Err(ReadFrameError::InvalidFrame(_)) => stream.write_avl_nack()?,
//!         Err(ReadFrameError::Closed) => break,
//!         Err(error) => return Err(error.into()),
//!     }
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```
//!
//! # Decoding your own buffer
//!
//! The IMEI and frame decoders come in two styles; a datagram is decoded
//! whole, so it has only `take_datagram`. `take_*` takes `input: &mut &[u8]`, a
//! cursor over bytes you own, in the style of
//! [winnow](https://docs.rs/winnow): on success the cursor moves past what
//! was decoded. `parse_*` takes `&[u8]` and returns the remaining bytes with
//! the result, in the style of [nom](https://docs.rs/nom). Either way the
//! result borrows the bytes it came from, and each error says where a cursor
//! is left and what can be done next; for a TCP frame:
//!
//! - [`Incomplete { needed }`](decoder::DecodeFrameError::Incomplete): the
//!   frame isn't all there. The cursor is untouched; read at least `needed`
//!   more bytes and call again. `needed` is exact.
//! - [`InvalidFrame`](decoder::DecodeFrameError::InvalidFrame): the frame is
//!   whole but wrong (bad CRC, unknown codec, malformed data). The cursor is
//!   past it; NACK it and go on.
//! - [`InvalidHeader`](decoder::DecodeFrameError::InvalidHeader): the
//!   preamble is wrong or the declared length is over the limit, so the next
//!   frame can't be found. The cursor is untouched. No device sends such a
//!   header: unless you want to search for the next preamble yourself, close
//!   the connection.
//!
//! [`take_frame`](decoder::take_frame) shows a read loop over a
//! growing buffer. A UDP datagram arrives whole, so
//! [`take_datagram`](decoder::take_datagram) never asks for more.
//!
//! # Views and owned values
//!
//! Decoders return views, such as [`FrameView`](protocol::FrameView): `Copy`
//! values over the decoded bytes. Everything that decides whether the packet
//! is valid (lengths, counts, CRC, enum bytes) is checked while decoding, so
//! a view can't fail afterwards; field values are read when you ask for them.
//! Call `evaluate` (with the `alloc` feature) to copy a view into an owned
//! value, such as [`Frame`](protocol::Frame), before the buffer is reused.
//! Views and owned values serialize the same way with `serde`.
//!
//! # Acknowledging
//!
//! Acknowledge what you stored, not what decoded: the device drops the
//! records it sees acknowledged. Over TCP, answer each AVL frame with the
//! number of records accepted, or 0 to have it sent again. Over UDP, answer
//! each datagram with its [`DatagramIds`](protocol::DatagramIds), which only
//! a datagram's header hands out, so an answer can't go to the wrong
//! packet; an invalid datagram's error carries them too, to answer it with
//! zero records.
//! Codec 12 commands go out only while the TCP connection stays open, after
//! the device's data is acknowledged.
//!
//! # Limits and memory
//!
//! - Codec 8 and Codec 8 Extended frames: 1280 bytes, preamble to CRC, as
//!   Teltonika documents.
//! - Any other frame (Codec 16, Codec 12, or an unsupported codec to skip):
//!   65,535 bytes, preamble to CRC. Teltonika states no limit for them; this
//!   one is the crate's.
//! - IMEI: any ASCII text of the length its 2-byte prefix declares, so up
//!   to 65,535 bytes.
//!
//! The limits bound what a peer can make a server hold and check. A length
//! over its limit is refused from the header that declares it, before any of
//! the bytes it announces are waited for, so a connection never buffers more
//! than 65,535 bytes for one frame, whatever is sent to it.
//!
//! A [`TeltonikaTcpStream`](tcp::TeltonikaTcpStream) starts with a
//! 1280-byte buffer, which `with_capacity` can raise. It grows once for a
//! longer frame and keeps that size until `shrink_to_fit` is called (see
//! its [Memory](tcp::TeltonikaTcpStream#memory) section). A
//! [`TeltonikaUdpSocket`](udp::TeltonikaUdpSocket) allocates 64 KiB once.
//! Decoders and encoders never allocate, except `evaluate` and the encoders
//! that return a `Vec`.
//!
//! # Features
//!
//! - `std` (default): the TCP stream, the UDP socket, and `SystemTime`
//!   conversions. Implies `alloc`.
//! - `alloc`: owned values and the encoders that return a `Vec`.
//! - `tokio`: `async` methods on the stream and the socket. Implies `std`.
//! - `serde`: serialization of views and owned values, and validated
//!   deserialization of [`Imei`](protocol::Imei).
//! - `chrono`: conversions between [`AvlTimestamp`](protocol::AvlTimestamp)
//!   and `DateTime<Utc>`.
//! - `tracing`: events from the stream and the socket, without IMEIs,
//!   positions, or payloads. Implies `std`.
//!
//! With `default-features = false` the crate is `no_std`: decoders, views,
//! and the encoders that write into a slice.
//!
//! # Caveats
//!
//! Where this crate reads the protocol in a way worth knowing:
//!
//! - **IO elements** are raw values. Their meaning comes from the device's
//!   "Teltonika Data Sending Parameters ID" page, not from this crate.
//! - **Codec 8 Extended** counts the variable-length elements (NX) in "N of
//!   Total IO", as devices send it, although the wiki's formula leaves NX
//!   out.
//! - **Positions** are kept as sent. A record without a GPS fix is valid
//!   data: check [`GpsElement::is_position_valid`](protocol::GpsElement::is_position_valid).
//! - **IMEIs** are ASCII text of the length the device declares, not
//!   necessarily 15 digits.
//! - **UDP**: the byte after the packet ID isn't checked; the wiki gives it a
//!   value only in acknowledgments.
//! - **Codec 12**: the first quantity gives the number of messages; the
//!   value of the second isn't read, as the wiki says it "will not be
//!   parsed". Payloads are bytes, usually ASCII text.
//! - **Codecs 13, 14, 15, and 17** aren't supported yet: their frames are
//!   skipped as invalid, and the connection goes on.
//! - **The stream reads ahead**: don't read the transport directly once
//!   wrapped. Its `async` reads are cancel-safe; its `async` writes are not.
//!
//! # Protocol sources
//!
//! Teltonika's wiki is the only source for the protocol:
//! [Data Sending Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
//! and [Codec](https://wiki.teltonika-gps.com/view/Codec). Where this crate
//! departs from it, the caveats above and the item docs say why.

#![warn(missing_docs)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

mod checksum;
#[cfg(test)]
#[path = "../tests/common/fixtures.rs"]
mod fixtures;
#[cfg(feature = "std")]
mod io;

pub mod decoder;
pub mod encoder;
pub mod protocol;

pub use checksum::crc16;

/// TCP connections: the IMEI handshake, frames, and the server's answers.
///
/// [`TeltonikaTcpStream`] wraps one connection, blocking or with Tokio. It
/// reads only when asked, waits for whole frames, returns views over its
/// buffer valid until the next read, and never acknowledges on its own.
/// Each read method returns an error type whose variants say whether the
/// connection can go on.
///
/// See the [crate docs](crate#a-tcp-session) for a whole session.
///
/// [`TeltonikaTcpStream`]: tcp::TeltonikaTcpStream
#[cfg(feature = "std")]
pub mod tcp {
    pub use crate::io::tcp::{
        ReadFrameError, ReadImeiError, TeltonikaTcpStream, WriteCommandError,
    };
}

/// UDP sockets: datagrams and their acknowledgments, addressed per device.
///
/// UDP is separate from [`tcp`] because a byte stream can't keep datagram
/// boundaries and source addresses. One [`TeltonikaUdpSocket`] serves every
/// device: each datagram comes with its source address, and each
/// acknowledgment goes to an explicit address with the IDs of the datagram
/// it answers.
///
/// [`TeltonikaUdpSocket`]: udp::TeltonikaUdpSocket
#[cfg(feature = "std")]
pub mod udp {
    pub use crate::io::udp::{ReceiveDatagramError, TeltonikaUdpSocket};
}

/// How to migrate from 0.1 and 0.2.0.
#[cfg(feature = "std")]
#[doc = include_str!("../docs/migration-0.3.md")]
pub mod migration {}

/// The README's examples, compiled and run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
