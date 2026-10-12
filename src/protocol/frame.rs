#[cfg(feature = "alloc")]
use super::{AvlPacket, GprsPacket};
use super::{AvlPacketView, Codec, GprsPacketView};

/// A TCP frame borrowed from the decoded buffer.
///
/// The frame is validated: its CRC matched and its data field is well
/// formed for its codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameView<'a> {
    /// AVL data: Codec 8, 8 Extended, or 16.
    Avl(AvlPacketView<'a>),
    /// GPRS messages: Codec 12 commands or responses.
    Gprs(GprsPacketView<'a>),
}

impl FrameView<'_> {
    /// Returns the codec of the frame.
    pub fn codec(&self) -> Codec {
        match self {
            Self::Avl(packet) => Codec::Avl(packet.codec()),
            Self::Gprs(packet) => Codec::Gprs(packet.codec()),
        }
    }

    /// Copies the frame into a [`Frame`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> Frame {
        match self {
            Self::Avl(packet) => Frame::Avl(packet.evaluate()),
            Self::Gprs(packet) => Frame::Gprs(packet.evaluate()),
        }
    }
}

/// A TCP frame that owns its data.
///
/// Obtained from a [`FrameView`] with [`FrameView::evaluate`] or [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum Frame {
    /// AVL data: Codec 8, 8 Extended, or 16.
    Avl(AvlPacket),
    /// GPRS messages: Codec 12 commands or responses.
    Gprs(GprsPacket),
}

#[cfg(feature = "alloc")]
impl Frame {
    /// Returns the codec of the frame.
    pub fn codec(&self) -> Codec {
        match self {
            Self::Avl(packet) => Codec::Avl(packet.codec()),
            Self::Gprs(packet) => Codec::Gprs(packet.codec()),
        }
    }
}

#[cfg(feature = "alloc")]
impl From<FrameView<'_>> for Frame {
    fn from(view: FrameView<'_>) -> Self {
        view.evaluate()
    }
}
