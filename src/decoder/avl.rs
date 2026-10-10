use core::fmt;

use crate::protocol::{
    AvlCodec, AvlPacketView, AvlRecordView, AvlTimestamp, GenerationType, GpsElement, Priority,
};

// Layouts: https://wiki.teltonika-gps.com/view/Codec, sections "Codec 8",
// "Codec 8 Extended", and "Codec 16" (accessed 2026-09-24). The data field
// runs from the codec ID to the second record count:
//
// | Codec ID | Number of Data 1 | AVL Data | Number of Data 2 |
// | 1 byte   | 1 byte           | X bytes  | 1 byte           |
//
// and each record of the AVL data is, with the widths of its codec:
//
// | Timestamp | Priority | GPS element | IO element |
// | 8 bytes   | 1 byte   | 15 bytes    | X bytes    |

/// Size of a record's timestamp: milliseconds in a `u64`.
const TIMESTAMP_LEN: usize = 8;

/// Size of a record's priority.
const PRIORITY_LEN: usize = 1;

/// Bytes of a record before its event IO ID, the same in every codec:
/// timestamp, priority, and GPS element.
pub(crate) const RECORD_HEAD_LEN: usize = TIMESTAMP_LEN + PRIORITY_LEN + GpsElement::LEN;

/// Value lengths of the four fixed-width IO groups, in the order sent: N1,
/// N2, N4, and N8.
const IO_VALUE_LENS: [usize; 4] = [1, 2, 4, 8];

/// Validates the data field of an AVL frame or datagram, from the codec ID
/// to the second record count.
///
/// Walks the records once to find where each ends and to check what makes a
/// packet invalid; their values are read later, from the returned view.
///
/// # Errors
///
/// Returns [`AvlPacketError`] for the first invalid field.
pub(crate) fn validate_avl_data(
    codec: AvlCodec,
    data: &[u8],
) -> Result<AvlPacketView<'_>, AvlPacketError> {
    let (&[_codec_id, count], start) = data.split_first_chunk().ok_or(AvlPacketError::Truncated)?;
    if count == 0 {
        return Err(AvlPacketError::NoRecords);
    }
    let mut rest = start;
    for _ in 0..count {
        take_record(codec, &mut rest)?;
    }
    let records = &start[..start.len() - rest.len()];
    match *rest {
        [] => Err(AvlPacketError::Truncated),
        [second] if second != count => Err(AvlPacketError::RecordCountMismatch {
            first: count,
            second,
        }),
        [_] => Ok(AvlPacketView {
            codec,
            count,
            records,
        }),
        _ => Err(AvlPacketError::TrailingBytes),
    }
}

/// Reads one AVL record of `codec`, moving `input` past it.
///
/// The record's scalar fields are read; its GPS element and its IO groups
/// are only delimited, each fixed-width group with one length check, and
/// kept as sub-slices for the view to read on access.
///
/// # Errors
///
/// Returns [`AvlPacketError::Truncated`] if the record runs past `input`,
/// [`AvlPacketError::InvalidPriority`] or
/// [`AvlPacketError::InvalidGenerationType`] for an unknown enum byte, and
/// [`AvlPacketError::IoCountMismatch`] if "N of Total IO" differs from
/// N1 + N2 + N4 + N8 (+ NX in Codec 8 Extended). `input` is left untouched.
pub(crate) fn take_record<'a>(
    codec: AvlCodec,
    input: &mut &'a [u8],
) -> Result<AvlRecordView<'a>, AvlPacketError> {
    const TRUNCATED: AvlPacketError = AvlPacketError::Truncated;

    let (head, mut rest) = input
        .split_first_chunk::<RECORD_HEAD_LEN>()
        .ok_or(TRUNCATED)?;
    let [t0, t1, t2, t3, t4, t5, t6, t7, priority, gps @ ..] = head;
    let timestamp = u64::from_be_bytes([*t0, *t1, *t2, *t3, *t4, *t5, *t6, *t7]);
    let priority = Priority::try_from(*priority).map_err(AvlPacketError::InvalidPriority)?;

    let event_io_id = take_uint(codec.id_len(), &mut rest).ok_or(TRUNCATED)?;
    let generation_type = match codec {
        AvlCodec::Codec16 => {
            let byte = *rest.split_off_first().ok_or(TRUNCATED)?;
            Some(GenerationType::try_from(byte).map_err(AvlPacketError::InvalidGenerationType)?)
        }
        AvlCodec::Codec8 | AvlCodec::Codec8Extended => None,
    };
    let io_count = take_uint(codec.count_len(), &mut rest).ok_or(TRUNCATED)?;

    let io_start = rest;
    let mut counted = 0;
    // The groups of 1-, 2-, 4-, and 8-byte values: a count, then that many
    // elements of the same length.
    for value_len in IO_VALUE_LENS {
        let count = take_uint(codec.count_len(), &mut rest).ok_or(TRUNCATED)?;
        let len = usize::from(count).saturating_mul(codec.id_len() + value_len);
        rest.split_off(..len).ok_or(TRUNCATED)?;
        counted += u32::from(count);
    }
    // The group of variable-length values: a count, then for each element a
    // 2-byte ID, a 2-byte length, and the value.
    if codec == AvlCodec::Codec8Extended {
        let count = take_uint(codec.count_len(), &mut rest).ok_or(TRUNCATED)?;
        for _ in 0..count {
            let (&[_, _, l0, l1], tail) = rest.split_first_chunk().ok_or(TRUNCATED)?;
            let len = usize::from(u16::from_be_bytes([l0, l1]));
            rest = tail.get(len..).ok_or(TRUNCATED)?;
        }
        counted += u32::from(count);
    }
    // The wiki states "N = N1 + N2 + N4 + N8" for every codec, but Codec 8
    // Extended devices also count their variable-length elements in it:
    // N = N1 + N2 + N4 + N8 + NX. The wiki's only Codec 8 Extended example
    // has NX = 0, so it agrees with both readings.
    if counted != u32::from(io_count) {
        return Err(AvlPacketError::IoCountMismatch {
            declared: io_count,
            counted,
        });
    }

    *input = rest;
    Ok(AvlRecordView {
        codec,
        timestamp: AvlTimestamp::from(timestamp),
        priority,
        gps,
        event_io_id,
        generation_type,
        io_count,
        io: &io_start[..io_start.len() - rest.len()],
    })
}

/// Reads a big-endian integer of `len` bytes, moving `input` past it.
///
/// `len` is 1 or 2: [`AvlCodec::id_len`] for an IO ID, [`AvlCodec::count_len`]
/// for an IO element count. Returns `None`, leaving `input` untouched, if
/// fewer than `len` bytes remain.
pub(crate) fn take_uint(len: usize, input: &mut &[u8]) -> Option<u16> {
    match *input.split_off(..len)? {
        [byte] => Some(u16::from(byte)),
        [high, low] => Some(u16::from_be_bytes([high, low])),
        _ => None,
    }
}

/// The error returned when the AVL data of a frame or datagram is invalid.
///
/// The frame or datagram was fully delimited, so the error concerns only its
/// content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AvlPacketError {
    /// The data ends before a field that the counts or lengths declare: the
    /// declared lengths are inconsistent.
    Truncated,
    /// The packet declares zero records.
    NoRecords,
    /// The two record counts differ ("Number of Data 2 […] must be the same
    /// as Number of Data 1").
    RecordCountMismatch {
        /// Number of Data 1, before the records.
        first: u8,
        /// Number of Data 2, after the records.
        second: u8,
    },
    /// Bytes remain after the second record count.
    TrailingBytes,
    /// A record's priority byte is not a [`Priority`].
    ///
    /// [`Priority`]: crate::protocol::Priority
    InvalidPriority(u8),
    /// A Codec 16 record's generation type byte is not a
    /// [`GenerationType`].
    ///
    /// [`GenerationType`]: crate::protocol::GenerationType
    InvalidGenerationType(u8),
    /// A record's "N of Total IO" differs from the number of elements in
    /// its groups: N1 + N2 + N4 + N8, plus NX in Codec 8 Extended.
    IoCountMismatch {
        /// N of Total IO, as declared.
        declared: u16,
        /// N1 + N2 + N4 + N8 (+ NX), as counted.
        counted: u32,
    },
}

impl fmt::Display for AvlPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("AVL data ends before its declared end"),
            Self::NoRecords => f.write_str("AVL packet declares no records"),
            Self::RecordCountMismatch { first, second } => {
                write!(f, "record counts differ: {first} before, {second} after")
            }
            Self::TrailingBytes => f.write_str("bytes after the second record count"),
            Self::InvalidPriority(byte) => write!(f, "invalid priority {byte:#04x}"),
            Self::InvalidGenerationType(byte) => {
                write!(f, "invalid generation type {byte:#04x}")
            }
            Self::IoCountMismatch { declared, counted } => write!(
                f,
                "IO element count is {declared}, but the groups hold {counted}"
            ),
        }
    }
}

impl core::error::Error for AvlPacketError {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use std::vec;

    use crate::decoder::take_frame;
    use crate::decoder::tests::frame;
    use crate::fixtures::{
        CODEC8, CODEC8_EXTENDED, CODEC8_SINGLE_RECORD_ALT, CODEC8_TWO_RECORDS, CODEC16, bytes,
        data_field,
    };

    use super::AvlPacketError;
    use crate::protocol::{
        AvlCodec, AvlPacketView, FrameView, GenerationType, IoId, IoValueView, Priority,
    };

    fn avl_packet(bytes: &[u8]) -> AvlPacketView<'_> {
        let mut input = bytes;
        let FrameView::Avl(packet) = take_frame(&mut input).unwrap() else {
            panic!("expected AVL data");
        };
        assert!(input.is_empty());
        packet
    }

    fn io(id: u16, value: IoValueView<'_>) -> (IoId, IoValueView<'_>) {
        (IoId::from(id), value)
    }

    /// "Codec 8 > Examples > 1st example" from
    /// https://wiki.teltonika-gps.com/view/Codec (accessed 2026-09-24).
    #[test]
    fn decodes_the_wiki_codec8_example() {
        let bytes = bytes(CODEC8);
        let packet = avl_packet(&bytes);
        assert_eq!(packet.codec(), AvlCodec::Codec8);

        let records: Vec<_> = packet.records().collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(u64::from(record.timestamp()), 0x0000_016b_40d8_ea30);
        assert_eq!(record.priority(), Priority::High);
        assert_eq!(record.gps().satellites, 0);
        assert!(!record.gps().is_position_valid());
        assert_eq!(record.event_io_id(), Some(IoId::from(0x01)));
        assert_eq!(record.generation_type(), None);

        let elements: Vec<_> = record
            .io_elements()
            .map(|element| (element.id(), element.value()))
            .collect();
        assert_eq!(
            elements,
            [
                io(0x15, IoValueView::U8(0x03)),
                io(0x01, IoValueView::U8(0x01)),
                io(0x42, IoValueView::U16(0x5e0f)),
                io(0xf1, IoValueView::U32(0x0000_601a)),
                io(0x4e, IoValueView::U64(0)),
            ]
        );
    }

    /// "Codec 8 > Examples > 2nd example" and "3rd example" from
    /// https://wiki.teltonika-gps.com/view/Codec (accessed 2026-10-10): one
    /// record with three IO elements, then two records with one each.
    #[test]
    fn decodes_the_other_wiki_codec8_examples() {
        let second = [(
            0x0000_016b_40d9_ad80,
            vec![
                io(0x15, IoValueView::U8(0x03)),
                io(0x01, IoValueView::U8(0x01)),
                io(0x42, IoValueView::U16(0x5e10)),
            ],
        )];
        let third = [
            (0x0000_016b_40d5_7b48, vec![io(0x01, IoValueView::U8(0x00))]),
            (0x0000_016b_40d5_c198, vec![io(0x01, IoValueView::U8(0x01))]),
        ];
        for (fixture, expected) in [
            (CODEC8_SINGLE_RECORD_ALT, &second[..]),
            (CODEC8_TWO_RECORDS, &third[..]),
        ] {
            let bytes = bytes(fixture);
            let packet = avl_packet(&bytes);
            assert_eq!(packet.codec(), AvlCodec::Codec8);
            assert_eq!(packet.records().len(), expected.len());
            for (record, (timestamp, elements)) in packet.records().zip(expected) {
                assert_eq!(u64::from(record.timestamp()), *timestamp);
                assert_eq!(record.priority(), Priority::High);
                assert_eq!(record.event_io_id(), Some(IoId::from(0x01)));
                let decoded: Vec<_> = record
                    .io_elements()
                    .map(|element| (element.id(), element.value()))
                    .collect();
                assert_eq!(&decoded, elements);
            }
        }
    }

    /// "Codec 8 Extended > Example" from
    /// https://wiki.teltonika-gps.com/view/Codec (accessed 2026-09-24).
    #[test]
    fn decodes_the_wiki_codec8_extended_example() {
        let bytes = bytes(CODEC8_EXTENDED);
        let packet = avl_packet(&bytes);
        assert_eq!(packet.codec(), AvlCodec::Codec8Extended);

        let record = packet.records().next().unwrap();
        assert_eq!(u64::from(record.timestamp()), 0x0000_016b_412c_ee00);
        assert_eq!(record.event_io_id(), Some(IoId::from(0x0001)));
        assert_eq!(record.generation_type(), None);

        let elements: Vec<_> = record
            .io_elements()
            .map(|element| (element.id(), element.value()))
            .collect();
        assert_eq!(
            elements,
            [
                io(0x0001, IoValueView::U8(0x01)),
                io(0x0011, IoValueView::U16(0x001d)),
                io(0x0010, IoValueView::U32(0x015e_2c88)),
                io(0x000b, IoValueView::U64(0x3544_c87a)),
                io(0x000e, IoValueView::U64(0x1dd7_e06a)),
            ]
        );
    }

    /// "Codec 16 > Example" from https://wiki.teltonika-gps.com/view/Codec
    /// (accessed 2026-09-24).
    ///
    /// The wiki's "Parsed data" table lists priority `01`, but its hex
    /// stream, whose CRC-16 `5FB3` checks out, has `00` in both records. The
    /// test follows the stream.
    #[test]
    fn decodes_the_wiki_codec16_example() {
        let bytes = bytes(CODEC16);
        let packet = avl_packet(&bytes);
        assert_eq!(packet.codec(), AvlCodec::Codec16);

        let records: Vec<_> = packet.records().collect();
        assert_eq!(records.len(), 2);
        for (record, timestamp, speed_io) in [
            (records[0], 0x0000_016b_dbc7_8330, 0x0027),
            (records[1], 0x0000_016b_dbc7_8718, 0x0026),
        ] {
            assert_eq!(u64::from(record.timestamp()), timestamp);
            assert_eq!(record.priority(), Priority::Low);
            assert_eq!(record.event_io_id(), Some(IoId::from(0x000b)));
            assert_eq!(record.generation_type(), Some(GenerationType::OnChange));

            let elements: Vec<_> = record
                .io_elements()
                .map(|element| (element.id(), element.value()))
                .collect();
            assert_eq!(
                elements,
                [
                    io(0x0001, IoValueView::U8(0x00)),
                    io(0x0003, IoValueView::U8(0x00)),
                    io(0x000b, IoValueView::U16(speed_io)),
                    io(0x0042, IoValueView::U16(0x563a)),
                ]
            );
        }
    }

    #[test]
    fn decodes_variable_length_io_elements() {
        let frame = frame(&variable_io_data());

        let packet = avl_packet(&frame);
        let record = packet.records().next().unwrap();
        assert_eq!(record.event_io_id(), None);
        let elements: Vec<_> = record
            .io_elements()
            .map(|element| (element.id(), element.value()))
            .collect();
        assert_eq!(
            elements,
            [
                io(0x0101, IoValueView::Bytes(b"ab")),
                io(0x0102, IoValueView::Bytes(b"")),
            ]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn evaluated_packet_matches_its_view() {
        use crate::protocol::{AvlPacket, IoValue};

        let bytes = bytes(CODEC16);
        let view = avl_packet(&bytes);
        let packet = AvlPacket::from(view);

        assert_eq!(packet.codec(), view.codec());
        assert_eq!(packet.records().len(), 2);
        for (record, view) in packet.records().iter().zip(view.records()) {
            assert_eq!(record.timestamp(), view.timestamp());
            assert_eq!(record.generation_type(), view.generation_type());
            assert_eq!(record.io_elements().len(), view.io_elements().len());
        }
        assert_eq!(
            packet.records()[1].io_elements()[2].value(),
            &IoValue::U16(0x0026)
        );
    }

    /// Data field of one Codec 8 Extended record with only NX elements:
    /// 0x0101 => "ab" and 0x0102 => "". N counts NX too, so it is 2.
    fn variable_io_data() -> Vec<u8> {
        let mut data = hex::decode("8e01").unwrap();
        data.extend_from_slice(&[0; 8 + 1 + 15]); // timestamp, priority, GPS
        data.extend_from_slice(
            &hex::decode(
                "0000 0002 0000 0000 0000 0000 0002 0101 0002 6162 0102 0000".replace(' ', ""),
            )
            .unwrap(),
        );
        data.push(0x01);
        data
    }

    /// Data field of "Codec 8 > Examples > 1st example": codec ID at 0, record
    /// count at 1, priority at 10, longitude at 11, latitude at 15, "N of
    /// Total IO" at 27, second count at 53.
    fn codec8_data() -> Vec<u8> {
        data_field(&bytes(CODEC8)).to_vec()
    }

    #[test]
    fn keeps_coordinates_out_of_range_as_sent() {
        let mut data = codec8_data();
        data[11..15].copy_from_slice(&i32::MAX.to_be_bytes());
        data[15..19].copy_from_slice(&i32::MIN.to_be_bytes());
        let packet = super::validate_avl_data(AvlCodec::Codec8, &data).unwrap();
        let gps = packet.records().next().unwrap().gps();
        assert_eq!(gps.longitude_raw, i32::MAX);
        assert_eq!(gps.latitude_raw, i32::MIN);
        assert!(!gps.is_position_valid());
    }

    fn error(codec: AvlCodec, data: &[u8]) -> AvlPacketError {
        super::validate_avl_data(codec, data).unwrap_err()
    }

    #[test]
    fn rejects_data_that_ends_early() {
        // Every codec reads its IDs and counts at its own widths, and only
        // Codec 8 Extended has variable-length elements.
        for (codec, data) in [
            (AvlCodec::Codec8, codec8_data()),
            (
                AvlCodec::Codec8Extended,
                data_field(&bytes(CODEC8_EXTENDED)).to_vec(),
            ),
            (AvlCodec::Codec8Extended, variable_io_data()),
            (AvlCodec::Codec16, data_field(&bytes(CODEC16)).to_vec()),
        ] {
            for end in 1..data.len() {
                assert_eq!(
                    error(codec, &data[..end]),
                    AvlPacketError::Truncated,
                    "{codec:?} truncated at {end}"
                );
            }
        }
    }

    #[test]
    fn rejects_zero_records() {
        assert_eq!(
            error(AvlCodec::Codec8, &[0x08, 0x00, 0x00]),
            AvlPacketError::NoRecords
        );
    }

    #[test]
    fn rejects_mismatched_record_counts() {
        let mut data = codec8_data();
        data[53] = 2;
        assert_eq!(
            error(AvlCodec::Codec8, &data),
            AvlPacketError::RecordCountMismatch {
                first: 1,
                second: 2
            }
        );
    }

    #[test]
    fn rejects_bytes_after_the_second_count() {
        let mut data = codec8_data();
        data.push(0);
        assert_eq!(
            error(AvlCodec::Codec8, &data),
            AvlPacketError::TrailingBytes
        );
    }

    #[test]
    fn rejects_every_priority_but_the_three_defined() {
        let mut data = codec8_data();
        for value in 0..=u8::MAX {
            data[10] = value;
            let decoded = super::validate_avl_data(AvlCodec::Codec8, &data)
                .map(|packet| packet.records().next().unwrap().priority());
            let expected = Priority::try_from(value).map_err(AvlPacketError::InvalidPriority);
            assert_eq!(decoded, expected);
            assert_eq!(decoded.is_ok(), value <= 2, "priority {value}");
        }
    }

    #[test]
    fn rejects_every_generation_type_but_the_eight_defined() {
        // "Codec 16 > Example" data field; the generation type is at 28.
        let mut data = data_field(&bytes(CODEC16)).to_vec();
        for value in 0..=u8::MAX {
            data[28] = value;
            let decoded = super::validate_avl_data(AvlCodec::Codec16, &data)
                .map(|packet| packet.records().next().unwrap().generation_type());
            let expected = GenerationType::try_from(value)
                .map(Some)
                .map_err(AvlPacketError::InvalidGenerationType);
            assert_eq!(decoded, expected);
            assert_eq!(decoded.is_ok(), value <= 7, "generation type {value}");
        }
    }

    #[test]
    fn rejects_a_total_io_count_that_differs_from_the_groups() {
        // The low byte of "N of Total IO" in each wiki example: one byte at
        // 27 in Codec 8, two at 28 in Codec 8 Extended, and one at 29, after
        // the generation type, in Codec 16.
        for (codec, fixture, index, counted) in [
            (AvlCodec::Codec8, CODEC8, 27, 5),
            (AvlCodec::Codec8Extended, CODEC8_EXTENDED, 29, 5),
            (AvlCodec::Codec16, CODEC16, 29, 4),
        ] {
            let mut data = data_field(&bytes(fixture)).to_vec();
            assert_eq!(data[index], counted);
            data[index] += 1;
            assert_eq!(
                error(codec, &data),
                AvlPacketError::IoCountMismatch {
                    declared: u16::from(counted) + 1,
                    counted: u32::from(counted),
                }
            );
        }
    }

    #[test]
    fn rejects_a_total_io_count_without_the_variable_elements() {
        // One Codec 8 Extended NX element whose N counts only N1 + N2 + N4 +
        // N8. Devices count NX in N (FM3001 and FMB003 captures).
        let mut data = vec![0x8e, 0x01];
        data.extend_from_slice(&[0; 8 + 1 + 15]);
        data.extend_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 2, b'a', b'b',
        ]);
        data.push(0x01);
        assert_eq!(
            error(AvlCodec::Codec8Extended, &data),
            AvlPacketError::IoCountMismatch {
                declared: 0,
                counted: 1
            }
        );
    }

    #[test]
    fn rejects_a_variable_io_value_past_the_end() {
        // One Codec 8 Extended NX element declaring 5 bytes but holding 2.
        let mut data = vec![0x8e, 0x01];
        data.extend_from_slice(&[0; 8 + 1 + 15]);
        data.extend_from_slice(&[
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 5, b'a', b'b',
        ]);
        data.push(0x01);
        assert_eq!(
            error(AvlCodec::Codec8Extended, &data),
            AvlPacketError::Truncated
        );
    }
}
