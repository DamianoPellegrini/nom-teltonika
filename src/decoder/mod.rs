//! Decoders and their errors.
//!
//! Three units cover what a device sends: the IMEI handshake that opens a
//! TCP connection, every TCP frame after it, and a UDP datagram. Each has a
//! decoder in two styles, which differ only in how they hand back the bytes
//! after the unit:
//!
//! | Unit | Cursor | Remainder |
//! | --- | --- | --- |
//! | IMEI handshake | [`take_imei`] | [`parse_imei`] |
//! | TCP frame | [`take_frame`] | [`parse_frame`] |
//! | UDP datagram | [`take_datagram`] | none: nothing remains after a datagram |
//!
//! - `take_*` takes a `&mut &[u8]` cursor and moves it past what it decoded,
//!   as [winnow](https://docs.rs/winnow) parsers do. Calls chain on the same
//!   cursor, and an invalid unit that could be delimited is skipped.
//! - `parse_*` takes a `&[u8]` and returns the remaining bytes with the
//!   result, as [nom](https://docs.rs/nom) parsers do. On error nothing is
//!   returned but the error.
//!
//! Both return views that borrow the input. Nothing is copied or converted
//! while decoding: a view keeps the sub-slices of its fields and reads them
//! when asked.
//!
//! TCP decoders take partial input: until the whole unit is buffered they
//! return `Incomplete` with the exact number of bytes missing. The UDP
//! decoder takes exactly one datagram, as a receive call returns it, and
//! never asks for more. Each error type documents where it leaves the cursor
//! and what the caller can do next.
//!
//! # Examples
//!
//! ```
//! use nom_teltonika::decoder::{parse_imei, take_imei, take_frame};
//! use nom_teltonika::protocol::FrameView;
//!
//! // An IMEI handshake, then the "getinfo" command of the Teltonika wiki.
//! let bytes = hex::decode(concat!(
//!     "000F333536333037303432343431303133",
//!     "000000000000000F0C010500000007676574696E666F0100004312",
//! ))?;
//! let mut input = &bytes[..];
//!
//! assert_eq!(take_imei(&mut input)?.as_str(), "356307042441013");
//! let FrameView::Gprs(packet) = take_frame(&mut input)? else {
//!     panic!("expected a GPRS frame");
//! };
//! assert_eq!(packet.messages().next().unwrap().payload(), b"getinfo");
//! assert!(input.is_empty());
//!
//! // The same handshake, with the remaining bytes returned.
//! let (rest, imei) = parse_imei(&bytes)?;
//! assert_eq!(imei.as_str(), "356307042441013");
//! assert_eq!(rest.len(), 27);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod avl;
mod datagram;
mod frame;
mod gprs;
mod imei;

pub use avl::AvlPacketError;
pub(crate) use avl::{RECORD_HEAD_LEN, take_record, take_uint};
pub(crate) use datagram::{DATAGRAM_LENGTH_LEN, DATAGRAM_NOT_USABLE};
pub use datagram::{DatagramError, DecodeDatagramError, take_datagram};
pub use frame::{DecodeFrameError, FrameError, HeaderError, parse_frame, take_frame};
pub(crate) use frame::{
    FRAME_CRC_LEN, FRAME_HEADER_LEN, FRAME_OVERHEAD, FRAME_PREAMBLE, MAX_CODEC8_FRAME_LEN,
    MAX_FRAME_LEN,
};
#[cfg(feature = "std")]
pub(crate) use frame::{frame_len, validate_frame};
pub use gprs::GprsPacketError;
pub(crate) use gprs::{MESSAGE_HEADER_LEN, take_message};
pub use imei::{DecodeImeiError, parse_imei, take_imei};
#[cfg(feature = "std")]
pub(crate) use imei::{IMEI_PREFIX_LEN, imei_len};

#[cfg(test)]
pub(crate) mod tests {
    use std::vec::Vec;

    /// Wraps a data field in a TCP frame with its CRC.
    pub(crate) fn frame(data: &[u8]) -> Vec<u8> {
        let mut frame = super::FRAME_PREAMBLE.to_vec();
        frame.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(data);
        frame.extend_from_slice(&u32::from(crate::checksum::crc16(data)).to_be_bytes());
        frame
    }
}
