//! Encoders for server answers, commands, and device packets.
//!
//! A server needs four answers: [`encode_imei_approval`] for the
//! handshake, [`encode_avl_ack`] and [`encode_avl_nack`] for TCP frames, and
//! [`encode_udp_ack`] for datagrams; and [`encode_gprs_frame_into`] with
//! [`GprsMessageType::Command`] to send commands. The encoders don't perform
//! I/O, and don't decide what to acknowledge: acknowledge what your
//! application stored.
//!
//! The device-side encoders, [`encode_avl_frame_into`],
//! [`encode_avl_datagram_into`], and [`encode_gprs_frame_into`] with
//! [`GprsMessageType::Response`], exist to simulate devices in tests and
//! benchmarks. They check their input against the codec, so whatever they
//! encode decodes back to the same values.
//!
//! Every encoder that builds a frame has a `*_into` form that writes into a
//! slice and returns the length, without `alloc`, and a form that returns a
//! `Vec`.
//!
//! # Examples
//!
//! ```
//! use nom_teltonika::encoder::{encode_avl_ack, encode_gprs_frame_into};
//! use nom_teltonika::protocol::GprsMessageType;
//!
//! assert_eq!(encode_avl_ack(3), [0, 0, 0, 3]);
//!
//! let mut frame = [0; 64];
//! let len = encode_gprs_frame_into(GprsMessageType::Command, &["getinfo"], &mut frame)?;
//! assert_eq!(len, 27);
//! # Ok::<(), nom_teltonika::encoder::EncodeGprsError>(())
//! ```
//!
//! [`GprsMessageType::Command`]: crate::protocol::GprsMessageType::Command
//! [`GprsMessageType::Response`]: crate::protocol::GprsMessageType::Response

mod ack;
mod avl;
mod gprs;

pub use ack::{encode_avl_ack, encode_avl_nack, encode_imei_approval, encode_udp_ack};
pub use avl::{
    AvlRecordFields, DatagramHeaderFields, EncodeAvlError, encode_avl_datagram_into,
    encode_avl_frame_into,
};
#[cfg(feature = "alloc")]
pub use avl::{encode_avl_datagram, encode_avl_frame};
#[cfg(feature = "alloc")]
pub use gprs::encode_gprs_frame;
pub use gprs::{EncodeGprsError, encode_gprs_frame_into};

use crate::checksum::crc16;
use crate::decoder::{FRAME_CRC_LEN, FRAME_HEADER_LEN, FRAME_PREAMBLE};

/// Writes `bytes` at the start of `out` and moves `out` past them.
///
/// Encoders compute the exact length first, check it against the limits and
/// the caller's buffer, and only then write: integers go through
/// `to_be_bytes` and this function.
///
/// # Panics
///
/// Panics if `out` is shorter than `bytes`, which means the length was
/// computed wrong.
fn put(out: &mut &mut [u8], bytes: &[u8]) {
    let (head, rest) = core::mem::take(out).split_at_mut(bytes.len());
    head.copy_from_slice(bytes);
    *out = rest;
}

/// Writes a TCP frame into `frame`, whose length is the frame's: preamble,
/// data length, the data field that `put_data` writes, and its CRC.
///
/// # Panics
///
/// Panics if `frame` is shorter than a header and a CRC, or if `put_data`
/// writes more than the space between them: the length was computed wrong.
fn put_frame(frame: &mut [u8], put_data: impl FnOnce(&mut &mut [u8])) {
    let (body, crc) = frame.split_at_mut(frame.len() - FRAME_CRC_LEN);
    let data_len =
        u32::try_from(body.len() - FRAME_HEADER_LEN).expect("a frame is at most 65,535 bytes");
    let mut rest = &mut *body;
    put(&mut rest, &FRAME_PREAMBLE);
    put(&mut rest, &data_len.to_be_bytes());
    put_data(&mut rest);
    debug_assert!(rest.is_empty(), "the frame length counted every byte");
    // The CRC covers the data field: from the codec ID to the second count.
    let checksum = crc16(&body[FRAME_HEADER_LEN..]);
    crc.copy_from_slice(&u32::from(checksum).to_be_bytes());
}
