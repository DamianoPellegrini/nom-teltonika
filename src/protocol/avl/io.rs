#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt, iter::FusedIterator};

use crate::decoder::take_uint;
use crate::protocol::AvlCodec;

/// An IO element ID.
///
/// Its meaning, size, multiplier, and units depend on the device model and
/// firmware: look it up in the device's "Teltonika Data Sending Parameters
/// ID" page. This crate never maps it.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::IoId;
///
/// assert_eq!(u16::from(IoId::from(239)), 239);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IoId(u16);

impl IoId {
    /// Creates an ID in `const` code, as [`From<u16>`](From) does elsewhere.
    pub(crate) const fn new(id: u16) -> Self {
        Self(id)
    }
}

impl From<u16> for IoId {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

impl From<IoId> for u16 {
    fn from(id: IoId) -> Self {
        id.0
    }
}

/// An IO element value borrowed from the decoded buffer.
///
/// Fixed-width values are read as unsigned big-endian integers. Their
/// signedness and scale are device-specific, like the ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoValueView<'a> {
    /// A 1-byte value.
    U8(u8),
    /// A 2-byte value.
    U16(u16),
    /// A 4-byte value.
    U32(u32),
    /// An 8-byte value.
    U64(u64),
    /// A variable-length value (Codec 8 Extended only).
    Bytes(&'a [u8]),
}

/// An IO element borrowed from the decoded buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IoElementView<'a> {
    id: IoId,
    value: IoValueView<'a>,
}

impl<'a> IoElementView<'a> {
    /// Returns the IO element ID.
    pub const fn id(&self) -> IoId {
        self.id
    }

    /// Returns the value.
    pub const fn value(&self) -> IoValueView<'a> {
        self.value
    }

    /// Copies the element into an [`IoElement`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> IoElement {
        IoElement {
            id: self.id,
            value: self.value.into(),
        }
    }
}

/// An IO element value that owns its data.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum IoValue {
    /// A 1-byte value.
    U8(u8),
    /// A 2-byte value.
    U16(u16),
    /// A 4-byte value.
    U32(u32),
    /// An 8-byte value.
    U64(u64),
    /// A variable-length value (Codec 8 Extended only).
    Bytes(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] Vec<u8>),
}

#[cfg(feature = "alloc")]
impl From<IoValueView<'_>> for IoValue {
    fn from(view: IoValueView<'_>) -> Self {
        match view {
            IoValueView::U8(value) => Self::U8(value),
            IoValueView::U16(value) => Self::U16(value),
            IoValueView::U32(value) => Self::U32(value),
            IoValueView::U64(value) => Self::U64(value),
            IoValueView::Bytes(bytes) => Self::Bytes(bytes.into()),
        }
    }
}

/// An IO element that owns its data.
///
/// Obtained from an [`IoElementView`] with [`IoElementView::evaluate`] or
/// [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IoElement {
    id: IoId,
    value: IoValue,
}

#[cfg(feature = "alloc")]
impl IoElement {
    /// Returns the IO element ID.
    pub const fn id(&self) -> IoId {
        self.id
    }

    /// Returns the value.
    pub const fn value(&self) -> &IoValue {
        &self.value
    }
}

#[cfg(feature = "alloc")]
impl From<IoElementView<'_>> for IoElement {
    fn from(view: IoElementView<'_>) -> Self {
        view.evaluate()
    }
}

/// An iterator over the IO elements of an AVL record, in the order sent.
///
/// Returned by [`AvlRecordView::io_elements`](crate::protocol::AvlRecordView::io_elements).
/// Each element is read from the record's bytes when the iterator reaches
/// it: the groups of 1-, 2-, 4-, and 8-byte values, each after its count,
/// then the variable-length group of Codec 8 Extended.
#[derive(Clone)]
pub struct IoElements<'a> {
    pub(super) codec: AvlCodec,
    /// The groups not read yet, starting at a count or inside a group.
    pub(super) rest: &'a [u8],
    /// Elements left in all the groups.
    pub(super) remaining: u16,
    /// Number of groups entered: 0 before the first count is read.
    pub(super) group: u8,
    /// Elements left in the group entered last.
    pub(super) in_group: u16,
}

impl<'a> Iterator for IoElements<'a> {
    type Item = IoElementView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // The groups were validated when the packet was decoded, so no read
        // below falls short.
        self.remaining = self.remaining.checked_sub(1)?;
        while self.in_group == 0 {
            self.in_group = take_uint(self.codec.count_len(), &mut self.rest)?;
            self.group += 1;
        }
        self.in_group -= 1;

        // Every group starts its elements with an ID of the codec's length:
        // the variable-length group exists only in Codec 8 Extended, whose
        // IDs are 2 bytes everywhere.
        let rest = &mut self.rest;
        let id = take_uint(self.codec.id_len(), rest)?;
        let value = match self.group {
            1 => IoValueView::U8(*rest.split_off_first()?),
            2 => IoValueView::U16(u16::from_be_bytes(*rest.split_off(..2)?.first_chunk()?)),
            3 => IoValueView::U32(u32::from_be_bytes(*rest.split_off(..4)?.first_chunk()?)),
            4 => IoValueView::U64(u64::from_be_bytes(*rest.split_off(..8)?.first_chunk()?)),
            // Variable length: a 2-byte length, then the value.
            _ => {
                let len = take_uint(2, rest)?;
                IoValueView::Bytes(rest.split_off(..usize::from(len))?)
            }
        };
        Some(IoElementView {
            id: IoId(id),
            value,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = usize::from(self.remaining);
        (len, Some(len))
    }
}

impl ExactSizeIterator for IoElements<'_> {}

impl FusedIterator for IoElements<'_> {}

impl fmt::Debug for IoElements<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}
