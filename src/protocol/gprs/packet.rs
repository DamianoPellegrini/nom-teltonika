#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt, iter::FusedIterator};

#[cfg(feature = "alloc")]
use super::message::GprsMessage;
use super::message::GprsMessageView;
use crate::decoder::take_message;
use crate::protocol::GprsCodec;

/// A GPRS packet borrowed from the decoded buffer: Codec 12 commands or
/// responses.
///
/// The packet is validated: its CRC matched, it holds the messages its first
/// quantity declares, at least one, and every message has a known type and
/// fits the data field. Messages are read from the packet's bytes on access
/// and can't fail. Convert the packet into a
/// [`GprsPacket`] with [`evaluate`](Self::evaluate) when it must outlive the
/// buffer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GprsPacketView<'a> {
    pub(crate) codec: GprsCodec,
    /// Number of messages: the packet's first quantity.
    pub(crate) count: u8,
    /// The messages, back to back.
    pub(crate) messages: &'a [u8],
}

impl<'a> GprsPacketView<'a> {
    /// Returns the codec, which decides the layout of the messages.
    pub const fn codec(&self) -> GprsCodec {
        self.codec
    }

    /// Returns an iterator over the messages, in the order sent.
    pub const fn messages(&self) -> GprsMessages<'a> {
        GprsMessages {
            remaining: self.count,
            rest: self.messages,
        }
    }

    /// Copies the packet into a [`GprsPacket`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> GprsPacket {
        GprsPacket {
            codec: self.codec(),
            messages: self.messages().map(GprsMessage::from).collect(),
        }
    }
}

impl fmt::Debug for GprsPacketView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GprsPacketView")
            .field("codec", &self.codec())
            .field("messages", &self.messages())
            .finish()
    }
}

/// An iterator over the messages of a GPRS packet, in the order sent.
///
/// Returned by [`GprsPacketView::messages`]. Each message is read from the
/// packet's bytes when the iterator reaches it, with the reader that
/// validated it.
#[derive(Clone)]
pub struct GprsMessages<'a> {
    remaining: u8,
    rest: &'a [u8],
}

impl<'a> Iterator for GprsMessages<'a> {
    type Item = GprsMessageView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        // The messages were validated when the packet was decoded, so the
        // read can't fail.
        take_message(&mut self.rest).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = usize::from(self.remaining);
        (len, Some(len))
    }
}

impl ExactSizeIterator for GprsMessages<'_> {}

impl FusedIterator for GprsMessages<'_> {}

impl fmt::Debug for GprsMessages<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// A GPRS packet that owns its messages.
///
/// Obtained from a [`GprsPacketView`] with [`GprsPacketView::evaluate`] or
/// [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GprsPacket {
    codec: GprsCodec,
    messages: Vec<GprsMessage>,
}

#[cfg(feature = "alloc")]
impl GprsPacket {
    /// Returns the codec the packet was sent with.
    pub const fn codec(&self) -> GprsCodec {
        self.codec
    }

    /// Returns the messages, in the order sent.
    pub fn messages(&self) -> &[GprsMessage] {
        &self.messages
    }
}

#[cfg(feature = "alloc")]
impl From<GprsPacketView<'_>> for GprsPacket {
    fn from(view: GprsPacketView<'_>) -> Self {
        view.evaluate()
    }
}
