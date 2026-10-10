mod gps;
mod io;
mod packet;
mod record;
mod timestamp;

pub use gps::GpsElement;
#[cfg(feature = "alloc")]
pub use io::{IoElement, IoValue};
pub use io::{IoElementView, IoElements, IoId, IoValueView};
#[cfg(feature = "alloc")]
pub use packet::AvlPacket;
pub use packet::{AvlPacketView, AvlRecords};
#[cfg(feature = "alloc")]
pub use record::AvlRecord;
pub use record::{AvlRecordView, GenerationType, Priority};
pub use timestamp::{AvlTimestamp, TimestampError};
