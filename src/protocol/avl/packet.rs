#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt, iter::FusedIterator};

#[cfg(feature = "alloc")]
use super::record::AvlRecord;
use super::record::AvlRecordView;
use crate::decoder::take_record;
use crate::protocol::AvlCodec;

/// An AVL packet borrowed from the decoded buffer.
///
/// The packet is validated: the record counts agree, every record is well
/// formed, and the CRC matched when it came from a TCP frame. Records are
/// read from the packet's bytes on access and can't fail. Convert it into an
/// [`AvlPacket`] with [`evaluate`](Self::evaluate) when it must outlive the
/// buffer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvlPacketView<'a> {
    pub(crate) codec: AvlCodec,
    /// Number of records, as the packet declares it twice.
    pub(crate) count: u8,
    /// The records, back to back.
    pub(crate) records: &'a [u8],
}

impl<'a> AvlPacketView<'a> {
    /// Returns the codec, which decides the layout of the records.
    pub const fn codec(&self) -> AvlCodec {
        self.codec
    }

    /// Returns an iterator over the records, in the order sent.
    ///
    /// Its length is the record count to acknowledge once the records are
    /// accepted.
    pub const fn records(&self) -> AvlRecords<'a> {
        AvlRecords {
            codec: self.codec,
            remaining: self.count,
            rest: self.records,
        }
    }

    /// Copies the packet into an [`AvlPacket`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> AvlPacket {
        AvlPacket {
            codec: self.codec(),
            records: self.records().map(AvlRecord::from).collect(),
        }
    }
}

impl fmt::Debug for AvlPacketView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvlPacketView")
            .field("codec", &self.codec())
            .field("records", &self.records())
            .finish()
    }
}

/// An iterator over the records of an AVL packet, in the order sent.
///
/// Returned by [`AvlPacketView::records`]. Each record is read from the
/// packet's bytes when the iterator reaches it, with the reader that
/// validated it.
#[derive(Clone)]
pub struct AvlRecords<'a> {
    codec: AvlCodec,
    remaining: u8,
    rest: &'a [u8],
}

impl<'a> Iterator for AvlRecords<'a> {
    type Item = AvlRecordView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        // The records were validated when the packet was decoded, so the
        // read can't fail.
        take_record(self.codec, &mut self.rest).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = usize::from(self.remaining);
        (len, Some(len))
    }
}

impl ExactSizeIterator for AvlRecords<'_> {}

impl FusedIterator for AvlRecords<'_> {}

impl fmt::Debug for AvlRecords<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// An AVL packet that owns its data.
///
/// Obtained from an [`AvlPacketView`] with [`AvlPacketView::evaluate`] or
/// [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AvlPacket {
    codec: AvlCodec,
    records: Vec<AvlRecord>,
}

#[cfg(feature = "alloc")]
impl AvlPacket {
    /// Returns the codec the packet was sent with.
    pub const fn codec(&self) -> AvlCodec {
        self.codec
    }

    /// Returns the records, in the order sent.
    pub fn records(&self) -> &[AvlRecord] {
        &self.records
    }
}

#[cfg(feature = "alloc")]
impl From<AvlPacketView<'_>> for AvlPacket {
    fn from(view: AvlPacketView<'_>) -> Self {
        view.evaluate()
    }
}
