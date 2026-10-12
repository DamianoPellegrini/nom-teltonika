//! Decoders and encoders for the protocols of Teltonika GPS trackers.
//!
//! Teltonika devices send AVL data (positions and IO readings) to a server over
//! TCP or UDP, and take text commands over TCP. This crate decodes what devices
//! send and encodes what servers answer. It also encodes device traffic, for
//! tests and benchmarks.
//!
//! The crate has no dependencies of its own and works without the standard
//! library. Decoders return views over your buffer and don't copy the packet.
//!
//! This crate is not a server. It does I/O only in the optional [`tcp`] and
//! [`udp`] wrappers, and it never sends an acknowledgment on its own. It
//! doesn't interpret IO elements, because IO IDs, sizes, and units depend on
//! the device model and firmware.
//!
//! # Choosing an entry point
//!
//! - For one TCP connection per device, blocking or with Tokio, wrap the
//!   connection in a [`TeltonikaTcpStream`](tcp::TeltonikaTcpStream). It
//!   buffers, waits for whole frames, and writes the answers.
//! - For UDP, wrap one socket in a
//!   [`TeltonikaUdpSocket`](udp::TeltonikaUdpSocket). One socket serves every
//!   device.
//! - With your own sockets, buffers, or runtime, or without `std`, call the
//!   functions in [`decoder`] on the bytes you have, and send what [`encoder`]
//!   returns.
//!
//! # A TCP session
//!
//! A device opens the connection by sending its IMEI. It then waits for one
//! byte from the server: `01` to continue, or `00` to be refused. After that it
//! sends AVL frames. After each frame it waits for the number of records the
//! server accepted, sent as four bytes. While the connection is open, the
//! server can send Codec 12 commands, and the device answers them in Codec 12
//! frames.
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
//!             // Store the records first. The device deletes the records you
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
//!         // The frame is consumed. Ask the device to send it again.
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
//! The IMEI and frame decoders have two styles:
//!
//! - `take_*` takes `input: &mut &[u8]`, a cursor over bytes you own, like
//!   [winnow](https://docs.rs/winnow) parsers. On success the cursor moves past
//!   what was decoded.
//! - `parse_*` takes `&[u8]` and returns the remaining bytes with the result,
//!   like [nom](https://docs.rs/nom) parsers.
//!
//! A datagram is decoded whole, so it has only `take_datagram`.
//!
//! In both styles the result borrows the bytes it was decoded from. Each error
//! documents where the cursor is left and what can be done next. For a TCP
//! frame:
//!
//! - [`Incomplete { needed }`](decoder::DecodeFrameError::Incomplete): The
//!   frame is not complete. The cursor is unchanged. Read at least `needed`
//!   more bytes and call again. `needed` is exact.
//! - [`InvalidFrame`](decoder::DecodeFrameError::InvalidFrame): The frame is
//!   complete but invalid, for example a bad CRC, an unknown codec, or
//!   malformed data. The cursor is past the frame. Send a NACK and continue.
//! - [`InvalidHeader`](decoder::DecodeFrameError::InvalidHeader): The preamble
//!   is wrong or the declared length is over the limit, so the next frame can't
//!   be found. The cursor is unchanged. No device sends such a header. Close
//!   the connection, unless you want to search for the next preamble yourself.
//!
//! [`take_frame`](decoder::take_frame) has an example of a read loop over a
//! growing buffer. A UDP datagram arrives whole, so
//! [`take_datagram`](decoder::take_datagram) never asks for more bytes.
//!
//! # Views and owned values
//!
//! Decoders return views, such as [`FrameView`](protocol::FrameView). A view is
//! a `Copy` value over the decoded bytes. Everything that makes a packet valid
//! is checked while decoding: lengths, counts, the CRC, and enum bytes. A view
//! therefore can't fail afterwards. Field values are read when you ask for
//! them.
//!
//! With the `alloc` feature, `evaluate` copies a view into an owned value, such
//! as [`Frame`](protocol::Frame). Call it before the buffer is reused. Views
//! and owned values serialize the same way with `serde`.
//!
//! # Acknowledging
//!
//! Acknowledge the records you stored, not the records that were decoded. The
//! device deletes the records it sees acknowledged.
//!
//! Over TCP, answer each AVL frame with the number of records accepted, or with
//! 0 to have the frame sent again.
//!
//! Over UDP, answer each datagram with its
//! [`DatagramIds`](protocol::DatagramIds). Only a datagram's header provides
//! them, so an answer can't go to the wrong packet. The error for an invalid
//! datagram has them too, to answer it with zero records.
//!
//! Codec 12 commands can be sent only while the TCP connection is open, after
//! the device's data is acknowledged.
//!
//! # Limits and memory
//!
//! - A Codec 8 or Codec 8 Extended frame can have 1280 bytes, from the preamble
//!   to the CRC, as Teltonika documents.
//! - Any other frame can have 65,535 bytes, from the preamble to the CRC. This
//!   covers Codec 16, Codec 12, and frames of an unsupported codec, which are
//!   skipped. Teltonika states no limit for these frames, so this limit is the
//!   crate's own.
//! - An IMEI is ASCII text of the length its 2-byte prefix declares, so it can
//!   have up to 65,535 bytes.
//!
//! The limits bound what a peer can make a server hold and check. A length over
//! its limit is rejected from the header that declares it, before the declared
//! bytes are waited for. A connection therefore never buffers more than 65,535
//! bytes for one frame.
//!
//! A [`TeltonikaTcpStream`](tcp::TeltonikaTcpStream) starts with a 1280-byte
//! buffer, which `with_capacity` can raise. The buffer grows once for a longer
//! frame and keeps that size until `shrink_to_fit` is called. See its
//! [Memory](tcp::TeltonikaTcpStream#memory) section. A
//! [`TeltonikaUdpSocket`](udp::TeltonikaUdpSocket) allocates 64 KiB once.
//! Decoders and encoders never allocate, except `evaluate` and the encoders
//! that return a `Vec`.
//!
//! # Features
//!
//! - `std` (default): The TCP stream, the UDP socket, and `SystemTime`
//!   conversions. Enables `alloc`.
//! - `alloc`: Owned values and the encoders that return a `Vec`.
//! - `tokio`: `async` methods on the stream and the socket. Enables `std`.
//! - `serde`: Serialization of views and owned values, and validated
//!   deserialization of [`Imei`](protocol::Imei).
//! - `chrono`: Conversions between [`AvlTimestamp`](protocol::AvlTimestamp) and
//!   `DateTime<Utc>`.
//! - `tracing`: Events from the stream and the socket, without IMEIs,
//!   positions, or payloads. Enables `std`.
//!
//! With `default-features = false` the crate is `no_std`. It then has the
//! decoders, the views, and the encoders that write into a slice.
//!
//! # Caveats
//!
//! Notes on how this crate reads the protocol:
//!
//! - IO elements are raw values. Their meaning is documented on the device's
//!   "Teltonika Data Sending Parameters ID" page, not in this crate.
//! - In Codec 8 Extended, "N of Total IO" includes the variable-length elements
//!   (NX), as devices send it. The wiki's formula leaves NX out.
//! - Positions are kept as sent. A record without a GPS fix is valid data.
//!   Check
//!   [`GpsElement::is_position_valid`](protocol::GpsElement::is_position_valid).
//! - An IMEI is ASCII text of the length the device declares. It is not
//!   necessarily 15 digits.
//! - In a UDP datagram, the byte after the packet ID isn't checked. The wiki
//!   gives it a value only in acknowledgments.
//! - In Codec 12, the first quantity gives the number of messages. The second
//!   quantity isn't read, because the wiki says it "will not be parsed".
//!   Payloads are bytes, usually ASCII text.
//! - Codecs 13, 14, 15, and 17 aren't supported yet. Their frames are skipped
//!   as invalid, and the connection continues.
//! - The stream reads ahead. Don't read the transport directly once it is
//!   wrapped. The stream's `async` reads are cancel-safe. Its `async` writes
//!   are not.
//!
//! # Protocol sources
//!
//! Teltonika's wiki is the only source for the protocol: [Data Sending
//! Protocols](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols)
//! and [Codec](https://wiki.teltonika-gps.com/view/Codec). The caveats above
//! and the item docs explain where this crate departs from it.

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

/// A wrapper for TCP connections.
///
/// [`TeltonikaTcpStream`] wraps one connection, blocking or with Tokio. It
/// reads only when asked and waits for whole frames. It returns views over
/// its buffer, which are valid until the next read. It never sends an
/// acknowledgment on its own. Each read method has its own error type,
/// whose variants tell whether the connection can continue.
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

/// A wrapper for UDP sockets.
///
/// UDP is separate from [`tcp`] because a byte stream can't keep datagram
/// boundaries and source addresses. One [`TeltonikaUdpSocket`] serves every
/// device. Each datagram is returned with its source address. Each
/// acknowledgment is sent to an explicit address, with the IDs of the
/// datagram it answers.
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
