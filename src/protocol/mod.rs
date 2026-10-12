//! Protocol values produced by the decoders.
//!
//! Every packet type comes in two forms. The view, such as
//! [`AvlPacketView`], is what a decoder returns: a `Copy` value over the
//! validated bytes, read on access. The type with the plain name, such as
//! [`AvlPacket`] (with the `alloc` feature), owns its data; it is built
//! from a view with `evaluate` or [`From`], and only that way, so holding
//! one proves the bytes were valid.
//!
//! | Unit | View | Owned |
//! | --- | --- | --- |
//! | TCP frame | [`FrameView`] | [`Frame`] |
//! | UDP datagram | [`DatagramView`] | [`Datagram`] |
//! | IMEI | [`ImeiView`] | [`Imei`] |
//! | AVL packet, record, IO element | [`AvlPacketView`], [`AvlRecordView`], [`IoElementView`] | [`AvlPacket`], [`AvlRecord`], [`IoElement`] |
//! | GPRS packet, message | [`GprsPacketView`], [`GprsMessageView`] | [`GprsPacket`], [`GprsMessage`] |
//!
//! Small fixed values have one form: [`AvlTimestamp`], [`GpsElement`],
//! [`IoId`], [`Priority`], [`GenerationType`], [`GprsMessageType`], the codec
//! enums, and [`DatagramIds`]. Enums sent as a byte convert from it with
//! [`TryFrom<u8>`](TryFrom) and back with [`From`].
//!
//! Values are kept as sent: coordinates in 10⁻⁷ degrees, timestamps in
//! milliseconds, IO values as unsigned integers or bytes. Methods such as
//! [`GpsElement::latitude_degrees`] interpret them.

mod avl;
mod codec;
mod datagram;
mod frame;
mod gprs;
mod imei;
#[cfg(feature = "serde")]
mod serialize;

#[cfg(feature = "alloc")]
pub use avl::{AvlPacket, AvlRecord, IoElement, IoValue};
pub use avl::{
    AvlPacketView, AvlRecordView, AvlRecords, AvlTimestamp, GenerationType, GpsElement,
    IoElementView, IoElements, IoId, IoValueView, Priority, TimestampError,
};
pub use codec::{AvlCodec, Codec, GprsCodec};
#[cfg(feature = "alloc")]
pub use datagram::Datagram;
pub use datagram::{DatagramIds, DatagramView};
#[cfg(feature = "alloc")]
pub use frame::Frame;
pub use frame::FrameView;
#[cfg(feature = "alloc")]
pub use gprs::{GprsMessage, GprsPacket};
pub use gprs::{GprsMessageType, GprsMessageView, GprsMessages, GprsPacketView};
#[cfg(feature = "alloc")]
pub use imei::Imei;
pub use imei::{ImeiError, ImeiView};
