// Codec IDs and field widths: https://wiki.teltonika-gps.com/view/Codec,
// sections "Codec 8", "Codec 8 Extended", "Codec 16", and "Codec 12"
// (accessed 2026-09-24).

use crate::decoder::{MAX_CODEC8_FRAME_LEN, MAX_FRAME_LEN};

/// The codec of a TCP frame, identified by its codec ID byte.
///
/// AVL data codecs and GPRS message codecs share the TCP framing but not the
/// layout of their data field, so each family has its own enum.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::{AvlCodec, Codec, GprsCodec};
///
/// assert_eq!(Codec::try_from(0x08), Ok(Codec::Avl(AvlCodec::Codec8)));
/// assert_eq!(Codec::try_from(0x0c), Ok(Codec::Gprs(GprsCodec::Codec12)));
/// assert_eq!(u8::from(Codec::Gprs(GprsCodec::Codec12)), 0x0c);
/// // Codec 13 is not supported yet.
/// assert_eq!(Codec::try_from(0x0d), Err(0x0d));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Codec {
    /// An AVL data codec.
    Avl(AvlCodec),
    /// A GPRS message codec.
    Gprs(GprsCodec),
}

/// An AVL data codec.
///
/// The codec decides the field widths of every record in a packet.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::AvlCodec;
///
/// assert_eq!(AvlCodec::try_from(0x8e), Ok(AvlCodec::Codec8Extended));
/// assert_eq!(u8::from(AvlCodec::Codec16), 0x10);
/// assert_eq!(AvlCodec::try_from(0x0c), Err(0x0c));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(u8)]
pub enum AvlCodec {
    /// Codec 8 (`0x08`).
    Codec8 = 0x08,
    /// Codec 8 Extended (`0x8e`).
    Codec8Extended = 0x8e,
    /// Codec 16 (`0x10`).
    Codec16 = 0x10,
}

/// A GPRS message codec, for commands and responses exchanged over an open
/// TCP session.
///
/// Only Codec 12 is supported; Codecs 13, 14, 15, and 17 may be added.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::GprsCodec;
///
/// assert_eq!(GprsCodec::try_from(0x0c), Ok(GprsCodec::Codec12));
/// assert_eq!(u8::from(GprsCodec::Codec12), 0x0c);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
#[repr(u8)]
pub enum GprsCodec {
    /// Codec 12 (`0x0c`).
    Codec12 = 0x0c,
}

impl TryFrom<u8> for Codec {
    /// The byte that is not a supported codec ID.
    type Error = u8;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        AvlCodec::try_from(id)
            .map(Self::Avl)
            .or_else(|id| GprsCodec::try_from(id).map(Self::Gprs))
    }
}

impl From<Codec> for u8 {
    fn from(codec: Codec) -> Self {
        match codec {
            Codec::Avl(codec) => codec.into(),
            Codec::Gprs(codec) => codec.into(),
        }
    }
}

impl TryFrom<u8> for AvlCodec {
    /// The byte that is not an AVL codec ID.
    type Error = u8;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        match id {
            0x08 => Ok(Self::Codec8),
            0x8e => Ok(Self::Codec8Extended),
            0x10 => Ok(Self::Codec16),
            other => Err(other),
        }
    }
}

impl From<AvlCodec> for u8 {
    fn from(codec: AvlCodec) -> Self {
        codec as u8
    }
}

impl TryFrom<u8> for GprsCodec {
    /// The byte that is not a supported GPRS codec ID.
    type Error = u8;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        match id {
            0x0c => Ok(Self::Codec12),
            other => Err(other),
        }
    }
}

impl From<GprsCodec> for u8 {
    fn from(codec: GprsCodec) -> Self {
        codec as u8
    }
}

impl AvlCodec {
    /// Returns the longest frame of the codec, from the preamble to the
    /// CRC: 1280 bytes for Codec 8 and Codec 8 Extended, as Teltonika
    /// documents, and the crate's own 65,535 for Codec 16, which has no
    /// documented limit. The decoders refuse a longer frame from its header,
    /// and the encoders don't build one.
    pub(crate) const fn max_frame_len(self) -> usize {
        match self {
            Self::Codec8 | Self::Codec8Extended => MAX_CODEC8_FRAME_LEN,
            Self::Codec16 => MAX_FRAME_LEN,
        }
    }

    /// Returns the number of bytes of an IO ID, the event IO ID included:
    /// one in Codec 8, two in Codec 8 Extended and Codec 16.
    pub(crate) const fn id_len(self) -> usize {
        match self {
            Self::Codec8 => 1,
            Self::Codec8Extended | Self::Codec16 => 2,
        }
    }

    /// Returns the number of bytes of an IO element count: two in Codec 8
    /// Extended, one in Codec 8 and Codec 16.
    pub(crate) const fn count_len(self) -> usize {
        match self {
            Self::Codec8Extended => 2,
            Self::Codec8 | Self::Codec16 => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Codec; 4] = [
        Codec::Avl(AvlCodec::Codec8),
        Codec::Avl(AvlCodec::Codec8Extended),
        Codec::Avl(AvlCodec::Codec16),
        Codec::Gprs(GprsCodec::Codec12),
    ];

    #[test]
    fn codecs_round_trip_through_their_id() {
        for codec in ALL {
            assert_eq!(Codec::try_from(u8::from(codec)), Ok(codec));
        }
    }

    #[test]
    fn other_ids_are_rejected_unchanged() {
        for id in 0..=u8::MAX {
            if !ALL.iter().any(|&codec| u8::from(codec) == id) {
                assert_eq!(Codec::try_from(id), Err(id));
            }
        }
    }
}
