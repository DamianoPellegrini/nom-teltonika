#[cfg(feature = "alloc")]
use super::{AvlPacket, Imei};
use super::{AvlPacketView, ImeiView};

/// The IDs that correlate a UDP acknowledgment with its datagram.
///
/// Obtained only from a datagram's header: with [`DatagramView::ids`] or
/// [`Datagram::ids`] when it decoded, or from
/// [`DecodeDatagramError::InvalidDatagram`](crate::decoder::DecodeDatagramError::InvalidDatagram)
/// when it didn't, to answer it with zero accepted records. Passed to
/// [`encode_udp_ack`](crate::encoder::encode_udp_ack). It is `Copy` and
/// doesn't borrow the datagram, so it can be kept until the records are
/// accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DatagramIds {
    packet_id: u16,
    avl_packet_id: u8,
}

impl DatagramIds {
    /// Creates the IDs read from a datagram's header.
    pub(crate) const fn new(packet_id: u16, avl_packet_id: u8) -> Self {
        Self {
            packet_id,
            avl_packet_id,
        }
    }

    /// Returns the packet ID of the UDP channel.
    pub const fn packet_id(&self) -> u16 {
        self.packet_id
    }

    /// Returns the ID of the AVL packet.
    pub const fn avl_packet_id(&self) -> u8 {
        self.avl_packet_id
    }
}

/// A UDP datagram carrying AVL data, borrowed from the decoded buffer.
///
/// The datagram is validated: its length matches, its IMEI is ASCII, and its
/// AVL packet is well formed. Acknowledge it with the packet ID and the AVL
/// packet ID it carries. Convert it into a [`Datagram`] with
/// [`evaluate`](Self::evaluate) when it must outlive the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramView<'a> {
    pub(crate) ids: DatagramIds,
    pub(crate) imei: ImeiView<'a>,
    pub(crate) packet: AvlPacketView<'a>,
}

impl<'a> DatagramView<'a> {
    /// Returns the packet ID of the UDP channel, echoed by the
    /// acknowledgment.
    pub const fn packet_id(&self) -> u16 {
        self.ids.packet_id
    }

    /// Returns the ID of the AVL packet, echoed by the acknowledgment.
    pub const fn avl_packet_id(&self) -> u8 {
        self.ids.avl_packet_id
    }

    /// Returns the IDs to acknowledge the datagram with.
    pub const fn ids(&self) -> DatagramIds {
        self.ids
    }

    /// Returns the IMEI of the sending device.
    pub const fn imei(&self) -> ImeiView<'a> {
        self.imei
    }

    /// Returns the AVL packet.
    pub const fn packet(&self) -> AvlPacketView<'a> {
        self.packet
    }

    /// Copies the datagram into a [`Datagram`] that outlives the buffer.
    #[cfg(feature = "alloc")]
    pub fn evaluate(self) -> Datagram {
        Datagram {
            ids: self.ids,
            imei: self.imei.evaluate(),
            packet: self.packet.evaluate(),
        }
    }
}

/// A UDP datagram carrying AVL data, owning its data.
///
/// Obtained from a [`DatagramView`] with [`DatagramView::evaluate`] or
/// [`From`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Datagram {
    ids: DatagramIds,
    imei: Imei,
    packet: AvlPacket,
}

#[cfg(feature = "alloc")]
impl Datagram {
    /// Returns the packet ID of the UDP channel, echoed by the
    /// acknowledgment.
    pub const fn packet_id(&self) -> u16 {
        self.ids.packet_id
    }

    /// Returns the ID of the AVL packet, echoed by the acknowledgment.
    pub const fn avl_packet_id(&self) -> u8 {
        self.ids.avl_packet_id
    }

    /// Returns the IDs to acknowledge the datagram with.
    pub const fn ids(&self) -> DatagramIds {
        self.ids
    }

    /// Returns the IMEI of the sending device.
    pub const fn imei(&self) -> &Imei {
        &self.imei
    }

    /// Returns the AVL packet.
    pub const fn packet(&self) -> &AvlPacket {
        &self.packet
    }
}

#[cfg(feature = "alloc")]
impl From<DatagramView<'_>> for Datagram {
    fn from(view: DatagramView<'_>) -> Self {
        view.evaluate()
    }
}
