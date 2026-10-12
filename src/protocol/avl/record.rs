#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "alloc")]
use super::io::IoElement;
use super::io::IoElements;
use crate::protocol::{AvlCodec, AvlTimestamp, GpsElement, IoId};

// Layouts: https://wiki.teltonika-gps.com/view/Codec, sections "Codec 8 > AVL
// Data", "Codec 8 Extended > AVL Data", and "Codec 16 > AVL Data" (accessed
// 2026-09-24).

/// The priority of an AVL record.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::Priority;
///
/// assert_eq!(Priority::try_from(2), Ok(Priority::Panic));
/// assert_eq!(u8::from(Priority::Low), 0);
/// assert_eq!(Priority::try_from(3), Err(3));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(u8)]
pub enum Priority {
    /// Low priority (`0`).
    Low = 0,
    /// High priority (`1`).
    High = 1,
    /// Panic priority (`2`).
    Panic = 2,
}

impl TryFrom<u8> for Priority {
    /// The byte that is not a priority.
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0 => Ok(Self::Low),
            1 => Ok(Self::High),
            2 => Ok(Self::Panic),
            other => Err(other),
        }
    }
}

impl From<Priority> for u8 {
    fn from(priority: Priority) -> Self {
        priority as u8
    }
}

/// What made a Codec 16 device generate a record.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::GenerationType;
///
/// assert_eq!(GenerationType::try_from(7), Ok(GenerationType::Periodical));
/// assert_eq!(u8::from(GenerationType::OnExit), 0);
/// assert_eq!(GenerationType::try_from(8), Err(8));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(u8)]
pub enum GenerationType {
    /// On exit (`0`).
    OnExit = 0,
    /// On entrance (`1`).
    OnEntrance = 1,
    /// On both (`2`).
    OnBoth = 2,
    /// Reserved (`3`).
    Reserved = 3,
    /// Hysteresis (`4`).
    Hysteresis = 4,
    /// On change (`5`).
    OnChange = 5,
    /// Eventual (`6`).
    Eventual = 6,
    /// Periodical (`7`).
    Periodical = 7,
}

impl TryFrom<u8> for GenerationType {
    /// The byte that is not a generation type.
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0 => Ok(Self::OnExit),
            1 => Ok(Self::OnEntrance),
            2 => Ok(Self::OnBoth),
            3 => Ok(Self::Reserved),
            4 => Ok(Self::Hysteresis),
            5 => Ok(Self::OnChange),
            6 => Ok(Self::Eventual),
            7 => Ok(Self::Periodical),
            other => Err(other),
        }
    }
}

impl From<GenerationType> for u8 {
    fn from(generation_type: GenerationType) -> Self {
        generation_type as u8
    }
}

/// An AVL record borrowed from the decoded buffer.
///
/// The record is validated: its GPS element and IO elements are read from
/// its bytes on access and can't fail. Convert it into an [`AvlRecord`] with
/// [`evaluate`](Self::evaluate) when it must outlive the buffer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvlRecordView<'a> {
    pub(crate) codec: AvlCodec,
    pub(crate) timestamp: AvlTimestamp,
    pub(crate) priority: Priority,
    /// The GPS element, as sent.
    pub(crate) gps: &'a [u8; GpsElement::LEN],
    /// The event IO ID as sent: 0 when the record is not eventual.
    pub(crate) event_io_id: u16,
    pub(crate) generation_type: Option<GenerationType>,
    /// Number of IO elements: "N of Total IO".
    pub(crate) io_count: u16,
    /// The IO element groups, from the count of the first one.
    pub(crate) io: &'a [u8],
}

impl<'a> AvlRecordView<'a> {
    /// Returns when the record was generated.
    pub const fn timestamp(&self) -> AvlTimestamp {
        self.timestamp
    }

    /// Returns the record priority.
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the GPS data.
    pub const fn gps(&self) -> GpsElement {
        GpsElement::from_bytes(self.gps)
    }

    /// Returns the ID of the IO element that generated the record, or
    /// `None` if the record is not eventual.
    pub const fn event_io_id(&self) -> Option<IoId> {
        // "If it's not eventual record – the value is 0."
        match self.event_io_id {
            0 => None,
            id => Some(IoId::new(id)),
        }
    }

    /// Returns what generated the record: always `Some` for Codec 16 and
    /// `None` for the other codecs.
    pub const fn generation_type(&self) -> Option<GenerationType> {
        self.generation_type
    }

    /// Returns an iterator over the IO elements, in the order sent: 1-, 2-,
    /// 4-, and 8-byte values, then variable-length values.
    pub const fn io_elements(&self) -> IoElements<'a> {
        IoElements {
            codec: self.codec,
            rest: self.io,
            remaining: self.io_count,
            group: 0,
            in_group: 0,
        }
    }

    /// Copies the record into an [`AvlRecord`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> AvlRecord {
        AvlRecord {
            timestamp: self.timestamp(),
            priority: self.priority(),
            gps: self.gps(),
            event_io_id: self.event_io_id(),
            generation_type: self.generation_type(),
            io_elements: self.io_elements().map(IoElement::from).collect(),
        }
    }
}

impl fmt::Debug for AvlRecordView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvlRecordView")
            .field("timestamp", &self.timestamp())
            .field("priority", &self.priority())
            .field("gps", &self.gps())
            .field("event_io_id", &self.event_io_id())
            .field("generation_type", &self.generation_type())
            .field("io_elements", &self.io_elements())
            .finish()
    }
}

/// An AVL record that owns its data.
///
/// Obtained from an [`AvlRecordView`] with [`AvlRecordView::evaluate`] or
/// [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AvlRecord {
    timestamp: AvlTimestamp,
    priority: Priority,
    gps: GpsElement,
    event_io_id: Option<IoId>,
    generation_type: Option<GenerationType>,
    io_elements: Vec<IoElement>,
}

#[cfg(feature = "alloc")]
impl AvlRecord {
    /// Returns when the record was generated.
    pub const fn timestamp(&self) -> AvlTimestamp {
        self.timestamp
    }

    /// Returns the record priority.
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the GPS data.
    pub const fn gps(&self) -> &GpsElement {
        &self.gps
    }

    /// Returns the ID of the IO element that generated the record, or
    /// `None` if the record is not eventual.
    pub const fn event_io_id(&self) -> Option<IoId> {
        self.event_io_id
    }

    /// Returns what generated the record: always `Some` for Codec 16 and
    /// `None` for the other codecs.
    pub const fn generation_type(&self) -> Option<GenerationType> {
        self.generation_type
    }

    /// Returns the IO elements, in the order sent.
    pub fn io_elements(&self) -> &[IoElement] {
        &self.io_elements
    }
}

#[cfg(feature = "alloc")]
impl From<AvlRecordView<'_>> for AvlRecord {
    fn from(view: AvlRecordView<'_>) -> Self {
        view.evaluate()
    }
}
