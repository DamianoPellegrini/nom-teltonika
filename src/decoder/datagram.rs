use core::fmt;

use super::avl::{AvlPacketError, validate_avl_data};
use super::imei::{DecodeImeiError, take_imei};
use crate::protocol::{AvlCodec, DatagramIds, DatagramView, ImeiError};

// Layout: https://wiki.teltonika-gps.com/view/Codec, section "Codec 8 >
// Codec8 protocol sending over UDP" (accessed 2026-09-24):
//
// | Length  | Packet ID | Not usable | AVL packet ID | IMEI length | IMEI    | AVL data array |
// | 2 bytes | 2 bytes   | 1 byte     | 1 byte        | 2 bytes     | X bytes | Y bytes        |
//
// "Length – packet length (excluding this field)". The AVL data array runs
// from the codec ID to the second record count; UDP has no CRC.

/// Size of the length field, which counts the bytes after itself.
pub(crate) const DATAGRAM_LENGTH_LEN: usize = 2;

/// The byte after the packet ID, as the wiki's examples have it: "not
/// usable" in a datagram, and written so in its acknowledgment.
pub(crate) const DATAGRAM_NOT_USABLE: u8 = 0x01;

/// Decodes one UDP datagram carrying AVL data, moving `input` past it.
///
/// `input` must hold exactly one whole datagram, as returned by a receive
/// call: the length field must match its size. A datagram arrives whole, so
/// a mismatch means it is malformed or was truncated by a small receive
/// buffer, never that more bytes are coming.
///
/// The "not usable" byte after the packet ID is not checked: the wiki gives
/// it a value (`0x01`) only in acknowledgments. The IMEI follows the same
/// rules as [`take_imei`], although the wiki says its length "always will be
/// 0x000F".
///
/// On success `input` is left empty, and the result borrows from it; convert
/// it with [`DatagramView::evaluate`] before the buffer is reused.
///
/// There is no `parse_datagram`: a datagram is decoded whole, so the bytes
/// it would return are always empty. With a plain slice, pass
/// `&mut &bytes[..]`.
///
/// # Errors
///
/// Returns [`DecodeDatagramError`] for the first thing wrong with the
/// datagram, and decodes nothing after it. `input` is left untouched. What
/// to answer, if anything, is the caller's choice: a datagram that has a
/// header comes with its IDs, to acknowledge zero records with
/// [`encode_udp_ack`](crate::encoder::encode_udp_ack).
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::take_datagram;
/// use nom_teltonika::protocol::AvlCodec;
///
/// // "Codec 8 > Codec8 protocol sending over UDP > Example" from the
/// // Teltonika wiki.
/// let bytes = hex::decode(
///     "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001",
/// )?;
/// let mut input = &bytes[..];
///
/// let datagram = take_datagram(&mut input)?;
/// assert_eq!(datagram.packet_id(), 0xcafe);
/// assert_eq!(datagram.avl_packet_id(), 0x05);
/// assert_eq!(datagram.imei().as_str(), "352093086403655");
/// assert_eq!(datagram.packet().codec(), AvlCodec::Codec8);
/// assert_eq!(datagram.packet().records().len(), 1);
/// assert!(input.is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn take_datagram<'a>(input: &mut &'a [u8]) -> Result<DatagramView<'a>, DecodeDatagramError> {
    // Length, packet ID, the byte that is not usable, and AVL packet ID.
    let (&[l0, l1, i0, i1, _not_usable, avl_packet_id], mut rest) = input
        .split_first_chunk()
        .ok_or(DecodeDatagramError::NoHeader)?;
    let ids = DatagramIds::new(u16::from_be_bytes([i0, i1]), avl_packet_id);
    let invalid = |reason| DecodeDatagramError::InvalidDatagram { ids, reason };

    let declared = u16::from_be_bytes([l0, l1]);
    let actual = input.len() - DATAGRAM_LENGTH_LEN;
    if actual != usize::from(declared) {
        return Err(invalid(DatagramError::LengthMismatch { declared, actual }));
    }
    let imei = take_imei(&mut rest).map_err(|error| match error {
        DecodeImeiError::Incomplete { .. } => invalid(DatagramError::Truncated),
        DecodeImeiError::NotAscii(error) => invalid(DatagramError::ImeiNotAscii(error)),
    })?;
    let &codec_id = rest.first().ok_or(invalid(DatagramError::Truncated))?;
    let codec =
        AvlCodec::try_from(codec_id).map_err(|id| invalid(DatagramError::UnsupportedCodec(id)))?;
    let packet =
        validate_avl_data(codec, rest).map_err(|error| invalid(DatagramError::Avl(error)))?;

    // The AVL data runs to the end of the datagram.
    *input = &[];
    Ok(DatagramView { ids, imei, packet })
}

/// The error returned by [`take_datagram`].
///
/// Either way the whole datagram is rejected, and the cursor is left
/// untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeDatagramError {
    /// The datagram is shorter than its header: it has no IDs to answer
    /// with.
    NoHeader,
    /// The datagram has a header, but is invalid.
    InvalidDatagram {
        /// The IDs read from the header, to answer the datagram with zero
        /// accepted records if you choose to. They are as trustworthy as
        /// the datagram.
        ids: DatagramIds,
        /// Why the datagram is invalid.
        reason: DatagramError,
    },
}

impl fmt::Display for DecodeDatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHeader => f.write_str("UDP datagram is shorter than its header"),
            Self::InvalidDatagram { .. } => f.write_str("invalid UDP datagram"),
        }
    }
}

impl core::error::Error for DecodeDatagramError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NoHeader => None,
            Self::InvalidDatagram { reason, .. } => Some(reason),
        }
    }
}

/// Why a UDP datagram with a header is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramError {
    /// The length field doesn't match the datagram size.
    LengthMismatch {
        /// Length declared by the length field, which excludes itself.
        declared: u16,
        /// Bytes after the length field.
        actual: usize,
    },
    /// The datagram ends before the IMEI its length declares, or before the
    /// codec ID.
    Truncated,
    /// The IMEI is not ASCII.
    ImeiNotAscii(ImeiError),
    /// The codec ID is not an AVL codec.
    UnsupportedCodec(u8),
    /// The AVL data is invalid.
    Avl(AvlPacketError),
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "UDP datagram declares {declared} bytes after its length, but has {actual}"
            ),
            Self::Truncated => f.write_str("UDP datagram ends before its declared end"),
            Self::ImeiNotAscii(_) => f.write_str("IMEI is not ASCII"),
            Self::UnsupportedCodec(id) => write!(f, "unsupported codec {id:#04x}"),
            Self::Avl(_) => f.write_str("invalid AVL data"),
        }
    }
}

impl core::error::Error for DatagramError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ImeiNotAscii(error) => Some(error),
            Self::Avl(error) => Some(error),
            Self::LengthMismatch { .. } | Self::Truncated | Self::UnsupportedCodec(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{IoId, IoValueView, Priority};

    /// "Codec 8 > Codec8 protocol sending over UDP > Example" from
    /// https://wiki.teltonika-gps.com/view/Codec (accessed 2026-09-24).
    const EXAMPLE: &str = crate::fixtures::UDP_CODEC8;

    #[test]
    fn decodes_the_wiki_example() {
        let bytes = hex::decode(EXAMPLE).unwrap();
        let mut input = &bytes[..];
        let datagram = take_datagram(&mut input).unwrap();

        assert!(input.is_empty());
        assert_eq!(datagram.packet_id(), 0xcafe);
        assert_eq!(datagram.avl_packet_id(), 0x05);
        assert_eq!(datagram.imei().as_str(), "352093086403655");
        // The same section: the server responds `0005CAFE010501`.
        assert_eq!(
            crate::encoder::encode_udp_ack(datagram.ids(), 1),
            [0x00, 0x05, 0xca, 0xfe, 0x01, 0x05, 0x01]
        );

        let record = datagram.packet().records().next().unwrap();
        assert_eq!(u64::from(record.timestamp()), 0x0000_016b_4f81_5b30);
        assert_eq!(record.priority(), Priority::High);
        assert_eq!(record.event_io_id(), Some(IoId::from(0x01)));
        let elements: std::vec::Vec<_> = record
            .io_elements()
            .map(|element| (element.id(), element.value()))
            .collect();
        assert_eq!(
            elements,
            [
                (IoId::from(0x15), IoValueView::U8(0x03)),
                (IoId::from(0x01), IoValueView::U8(0x01)),
                (IoId::from(0x42), IoValueView::U16(0x5dbc)),
            ]
        );
    }

    #[test]
    fn decodes_every_avl_codec() {
        // The wiki has a UDP example for Codec 8 only. These datagrams are
        // its header followed by the data field of each TCP example, which
        // is what "Codec8 protocol sending over UDP" says a datagram holds.
        use crate::fixtures::{CODEC8, CODEC8_EXTENDED, CODEC16, bytes, data_field};
        use crate::protocol::FrameView;

        let example = hex::decode(EXAMPLE).unwrap();
        for fixture in [CODEC8, CODEC8_EXTENDED, CODEC16] {
            let frame = bytes(fixture);
            let Ok(FrameView::Avl(sent)) = crate::decoder::take_frame(&mut &frame[..]) else {
                panic!("expected AVL data");
            };
            // Length, then packet ID to IMEI, then the data field.
            let data = data_field(&frame);
            let mut bytes = u16::try_from(21 + data.len())
                .unwrap()
                .to_be_bytes()
                .to_vec();
            bytes.extend_from_slice(&example[2..23]);
            bytes.extend_from_slice(data);

            let datagram = take_datagram(&mut &bytes[..]).unwrap();
            assert_eq!(datagram.imei().as_str(), "352093086403655");
            assert_eq!(datagram.packet(), sent);
        }
    }

    /// Decodes a datagram expected to be invalid, checking that `input` is
    /// left untouched and that the error carries the example's IDs.
    fn error(bytes: &[u8]) -> DatagramError {
        let mut input = bytes;
        let error = take_datagram(&mut input).unwrap_err();
        assert_eq!(input, bytes, "input must be left untouched");
        let DecodeDatagramError::InvalidDatagram { ids, reason } = error else {
            panic!("expected a datagram with a header");
        };
        assert_eq!((ids.packet_id(), ids.avl_packet_id()), (0xcafe, 0x05));
        reason
    }

    #[test]
    fn rejects_a_datagram_shorter_than_its_header() {
        let bytes = hex::decode(EXAMPLE).unwrap();
        for end in 0..6 {
            assert_eq!(
                take_datagram(&mut &bytes[..end]).unwrap_err(),
                DecodeDatagramError::NoHeader
            );
        }
    }

    #[test]
    fn rejects_a_length_mismatch() {
        let bytes = hex::decode(EXAMPLE).unwrap();
        let len = bytes.len();
        assert_eq!(
            error(&bytes[..len - 1]),
            DatagramError::LengthMismatch {
                declared: 0x3d,
                actual: 0x3c,
            }
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            error(&longer),
            DatagramError::LengthMismatch {
                declared: 0x3d,
                actual: 0x3e,
            }
        );
    }

    #[test]
    fn rejects_an_invalid_imei() {
        let mut bytes = hex::decode(EXAMPLE).unwrap();
        bytes[8] = 0xe9;
        assert_eq!(
            error(&bytes),
            DatagramError::ImeiNotAscii(ImeiError { index: 0 })
        );

        // A shorter IMEI than sent: its 15th digit is read as the codec ID.
        let mut bytes = hex::decode(EXAMPLE).unwrap();
        bytes[7] = 14;
        assert_eq!(error(&bytes), DatagramError::UnsupportedCodec(b'5'));

        // A longer IMEI than the datagram holds.
        let mut bytes = hex::decode(EXAMPLE).unwrap();
        bytes[6..8].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(error(&bytes), DatagramError::Truncated);
    }

    #[test]
    fn rejects_non_avl_codecs_and_invalid_avl_data() {
        let mut bytes = hex::decode(EXAMPLE).unwrap();
        bytes[23] = 0x0c;
        assert_eq!(error(&bytes), DatagramError::UnsupportedCodec(0x0c));

        let mut bytes = hex::decode(EXAMPLE).unwrap();
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert_eq!(
            error(&bytes),
            DatagramError::Avl(AvlPacketError::RecordCountMismatch {
                first: 1,
                second: 2,
            })
        );
    }

    #[test]
    fn ignores_the_not_usable_byte() {
        let mut bytes = hex::decode(EXAMPLE).unwrap();
        bytes[4] = 0x7f;
        assert!(take_datagram(&mut &bytes[..]).is_ok());
    }

    #[test]
    fn accepts_an_imei_of_any_ascii_text() {
        let mut bytes = hex::decode(EXAMPLE).unwrap();
        bytes[8] = b'x';
        let datagram = take_datagram(&mut &bytes[..]).unwrap();
        assert_eq!(datagram.imei().as_str(), "x52093086403655");
    }
}
