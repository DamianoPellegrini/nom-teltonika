#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use super::GprsMessageType;

/// A GPRS command or response borrowed from the decoded buffer.
///
/// The message is validated: its type is known and its payload fits the
/// frame. Fields that only some codecs carry will be added as methods
/// returning `Option`. Convert it into a [`GprsMessage`] with
/// [`evaluate`](Self::evaluate) when it must outlive the buffer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GprsMessageView<'a> {
    pub(crate) kind: GprsMessageType,
    pub(crate) payload: &'a [u8],
}

impl<'a> GprsMessageView<'a> {
    /// Returns whether the message is a command or a response.
    pub const fn kind(&self) -> GprsMessageType {
        self.kind
    }

    /// Returns the payload.
    ///
    /// Commands and responses are usually ASCII text, but the protocol
    /// doesn't require it.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Copies the message into a [`GprsMessage`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> GprsMessage {
        GprsMessage {
            kind: self.kind(),
            payload: self.payload().into(),
        }
    }
}

impl fmt::Debug for GprsMessageView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GprsMessageView")
            .field("kind", &self.kind())
            .field("payload", &self.payload())
            .finish()
    }
}

/// A GPRS command or response that owns its payload.
///
/// Obtained from a [`GprsMessageView`] with [`GprsMessageView::evaluate`] or
/// [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GprsMessage {
    kind: GprsMessageType,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    payload: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl GprsMessage {
    /// Returns whether the message is a command or a response.
    pub const fn kind(&self) -> GprsMessageType {
        self.kind
    }

    /// Returns the payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(feature = "alloc")]
impl From<GprsMessageView<'_>> for GprsMessage {
    fn from(view: GprsMessageView<'_>) -> Self {
        view.evaluate()
    }
}
