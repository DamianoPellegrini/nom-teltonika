#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use super::{put, put_frame};
use crate::decoder::{DATAGRAM_LENGTH_LEN, DATAGRAM_NOT_USABLE, FRAME_OVERHEAD, RECORD_HEAD_LEN};
use crate::protocol::{
    AvlCodec, AvlTimestamp, GenerationType, GpsElement, ImeiView, IoId, Priority,
};

// Layouts: https://wiki.teltonika-gps.com/view/Codec, sections "Codec 8",
// "Codec 8 Extended", "Codec 16", and "Codec 8 > Codec8 protocol sending over
// UDP" (accessed 2026-09-24).

/// The fields of one AVL record to encode.
///
/// Created with [`new`](Self::new) from the fields every record has, then
/// completed with the `with_*` methods. Nothing is checked here: the fields
/// are checked against the codec when the record is encoded, by
/// [`encode_avl_frame_into`] or [`encode_avl_datagram_into`].
///
/// IO elements are given per value width, the order they are sent in;
/// within a width, they keep the order given.
///
/// # Examples
///
/// ```
/// use nom_teltonika::encoder::AvlRecordFields;
/// use nom_teltonika::protocol::{AvlTimestamp, GpsElement, IoId, Priority};
///
/// let gps = GpsElement {
///     longitude_raw: 254_732_167,
///     latitude_raw: 546_991_882,
///     altitude_meters: 120,
///     angle_degrees: 90,
///     satellites: 9,
///     speed_kph: 42,
/// };
/// let ignition = [(IoId::from(239), 1)];
/// let record = AvlRecordFields::new(AvlTimestamp::from(1_560_161_086_000), Priority::High, gps)
///     .with_event_io_id(IoId::from(239))
///     .with_io_u8(&ignition);
/// # let _ = record;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvlRecordFields<'a> {
    timestamp: AvlTimestamp,
    priority: Priority,
    gps: GpsElement,
    event_io_id: Option<IoId>,
    generation_type: Option<GenerationType>,
    io_u8: &'a [(IoId, u8)],
    io_u16: &'a [(IoId, u16)],
    io_u32: &'a [(IoId, u32)],
    io_u64: &'a [(IoId, u64)],
    io_bytes: &'a [(IoId, &'a [u8])],
}

impl<'a> AvlRecordFields<'a> {
    /// Creates a record with no event IO ID, no generation type, and no IO
    /// elements.
    pub const fn new(timestamp: AvlTimestamp, priority: Priority, gps: GpsElement) -> Self {
        Self {
            timestamp,
            priority,
            gps,
            event_io_id: None,
            generation_type: None,
            io_u8: &[],
            io_u16: &[],
            io_u32: &[],
            io_u64: &[],
            io_bytes: &[],
        }
    }

    /// Sets the ID of the IO element that generated the record.
    ///
    /// Without it the record is not eventual, sent as ID 0; so ID 0 itself
    /// is rejected when encoding.
    pub const fn with_event_io_id(mut self, id: IoId) -> Self {
        self.event_io_id = Some(id);
        self
    }

    /// Sets what generated the record, which Codec 16 requires and the
    /// other codecs don't carry.
    pub const fn with_generation_type(mut self, generation_type: GenerationType) -> Self {
        self.generation_type = Some(generation_type);
        self
    }

    /// Sets the IO elements with 1-byte values.
    pub const fn with_io_u8(mut self, elements: &'a [(IoId, u8)]) -> Self {
        self.io_u8 = elements;
        self
    }

    /// Sets the IO elements with 2-byte values.
    pub const fn with_io_u16(mut self, elements: &'a [(IoId, u16)]) -> Self {
        self.io_u16 = elements;
        self
    }

    /// Sets the IO elements with 4-byte values.
    pub const fn with_io_u32(mut self, elements: &'a [(IoId, u32)]) -> Self {
        self.io_u32 = elements;
        self
    }

    /// Sets the IO elements with 8-byte values.
    pub const fn with_io_u64(mut self, elements: &'a [(IoId, u64)]) -> Self {
        self.io_u64 = elements;
        self
    }

    /// Sets the IO elements with variable-length values, which only Codec 8
    /// Extended carries.
    pub const fn with_io_bytes(mut self, elements: &'a [(IoId, &'a [u8])]) -> Self {
        self.io_bytes = elements;
        self
    }
}

/// Encodes AVL records into a TCP frame in `out` and returns the frame
/// length.
///
/// This is what a device sends: preamble, data length, codec ID, the record
/// count, the records, the count again, and the CRC. The frame always
/// decodes back with [`take_frame`](crate::decoder::take_frame)
/// to the same values. Use it to simulate a device.
///
/// # Errors
///
/// Returns [`EncodeAvlError`] when a record doesn't fit `codec` or the frame
/// is longer than the decoders accept (1280 bytes for Codec 8 and Codec 8
/// Extended, 65,535 for Codec 16), and [`EncodeAvlError::BufferTooSmall`]
/// with the frame length when `out` can't hold it. `out` is left unchanged
/// on error.
///
/// # Examples
///
/// ```
/// use nom_teltonika::encoder::{AvlRecordFields, encode_avl_frame_into};
/// use nom_teltonika::protocol::{AvlCodec, AvlTimestamp, GpsElement, IoId, Priority};
///
/// // "Codec 8 > Codec 8 protocol sending over TCP > Examples > 1st example"
/// // from the Teltonika wiki.
/// let gps = GpsElement {
///     longitude_raw: 0,
///     latitude_raw: 0,
///     altitude_meters: 0,
///     angle_degrees: 0,
///     satellites: 0,
///     speed_kph: 0,
/// };
/// let io_u8 = [(IoId::from(0x15), 3), (IoId::from(0x01), 1)];
/// let io_u16 = [(IoId::from(0x42), 0x5e0f)];
/// let io_u32 = [(IoId::from(0xf1), 0x601a)];
/// let io_u64 = [(IoId::from(0x4e), 0)];
/// let record = AvlRecordFields::new(AvlTimestamp::from(0x016b_40d8_ea30), Priority::High, gps)
///     .with_event_io_id(IoId::from(0x01))
///     .with_io_u8(&io_u8)
///     .with_io_u16(&io_u16)
///     .with_io_u32(&io_u32)
///     .with_io_u64(&io_u64);
///
/// let mut buffer = [0; 128];
/// let len = encode_avl_frame_into(AvlCodec::Codec8, &[record], &mut buffer)?;
/// assert_eq!(
///     buffer[..len],
///     hex::decode("000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF")?
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encode_avl_frame_into(
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
    out: &mut [u8],
) -> Result<usize, EncodeAvlError> {
    let len = checked_frame_len(codec, records)?;
    let Some(frame) = out.get_mut(..len) else {
        return Err(EncodeAvlError::BufferTooSmall { needed: len });
    };
    put_frame(frame, |out| put_data(out, codec, records));
    Ok(len)
}

/// Returns the length of the frame holding `records`, from its preamble to
/// its CRC. Checks every record against `codec`, and the frame against the
/// limit the decoders set for `codec`.
///
/// # Errors
///
/// Returns [`EncodeAvlError`], as [`checked_data_len`] does, and
/// [`EncodeAvlError::TooLong`] for a frame over the limit.
fn checked_frame_len(
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
) -> Result<usize, EncodeAvlError> {
    let len = FRAME_OVERHEAD + checked_data_len(codec, records)?;
    let limit = codec.max_frame_len();
    if len > limit {
        return Err(EncodeAvlError::TooLong { len, limit });
    }
    Ok(len)
}

/// Encodes AVL records into a new TCP frame.
///
/// See [`encode_avl_frame_into`] for the layout.
///
/// # Errors
///
/// Returns [`EncodeAvlError`] when a record doesn't fit `codec` or the frame
/// is longer than the decoders accept: 1280 bytes for Codec 8 and Codec 8
/// Extended, 65,535 for Codec 16.
#[cfg(feature = "alloc")]
pub fn encode_avl_frame(
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
) -> Result<Vec<u8>, EncodeAvlError> {
    let mut frame = alloc::vec![0; checked_frame_len(codec, records)?];
    put_frame(&mut frame, |out| put_data(out, codec, records));
    Ok(frame)
}

/// The IDs and IMEI that open a UDP datagram, as a device sends them.
///
/// The server echoes both IDs in its acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramHeaderFields<'a> {
    /// Packet ID of the UDP channel.
    pub packet_id: u16,
    /// ID of the AVL packet.
    pub avl_packet_id: u8,
    /// IMEI of the sending device.
    pub imei: ImeiView<'a>,
}

/// Encodes AVL records into a UDP datagram in `out` and returns the
/// datagram length.
///
/// Layout: length, packet ID, the byte `0x01`, AVL packet ID, IMEI length
/// and IMEI, then the AVL data as in a TCP frame, without CRC. The datagram
/// always decodes back with
/// [`take_datagram`](crate::decoder::take_datagram).
///
/// # Errors
///
/// Returns [`EncodeAvlError`] when a record doesn't fit `codec` or the
/// datagram is too long for its 2-byte length field,
/// and [`EncodeAvlError::BufferTooSmall`] with the datagram length when `out`
/// can't hold it. `out` is left unchanged on error.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::take_datagram;
/// use nom_teltonika::encoder::{AvlRecordFields, DatagramHeaderFields, encode_avl_datagram_into};
/// use nom_teltonika::protocol::{AvlCodec, AvlTimestamp, GpsElement, ImeiView, Priority};
///
/// let header = DatagramHeaderFields {
///     packet_id: 0xcafe,
///     avl_packet_id: 0x05,
///     imei: ImeiView::try_from("352093086403655")?,
/// };
/// let gps = GpsElement {
///     longitude_raw: 0,
///     latitude_raw: 0,
///     altitude_meters: 0,
///     angle_degrees: 0,
///     satellites: 0,
///     speed_kph: 0,
/// };
/// let record = AvlRecordFields::new(AvlTimestamp::from(0), Priority::Low, gps);
///
/// let mut buffer = [0; 128];
/// let len = encode_avl_datagram_into(header, AvlCodec::Codec8, &[record], &mut buffer)?;
/// let datagram = take_datagram(&mut &buffer[..len])?;
/// assert_eq!(datagram.packet_id(), 0xcafe);
/// assert_eq!(datagram.imei().as_str(), "352093086403655");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encode_avl_datagram_into(
    header: DatagramHeaderFields<'_>,
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
    out: &mut [u8],
) -> Result<usize, EncodeAvlError> {
    let len = checked_datagram_len(header, codec, records)?;
    let Some(datagram) = out.get_mut(..len) else {
        return Err(EncodeAvlError::BufferTooSmall { needed: len });
    };
    put_datagram(datagram, header, codec, records);
    Ok(len)
}

/// Returns the length of the datagram holding `records`, its length field
/// included. Checks every record against `codec`, and the datagram against
/// what its length field can declare.
///
/// # Errors
///
/// Returns [`EncodeAvlError`], as [`checked_data_len`] does, and
/// [`EncodeAvlError::TooLong`] for a datagram over the limit.
fn checked_datagram_len(
    header: DatagramHeaderFields<'_>,
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
) -> Result<usize, EncodeAvlError> {
    let len = DATAGRAM_HEADER_LEN + header.imei.len() + checked_data_len(codec, records)?;
    if len > MAX_DATAGRAM_LEN {
        return Err(EncodeAvlError::TooLong {
            len,
            limit: MAX_DATAGRAM_LEN,
        });
    }
    Ok(len)
}

/// Writes the datagram holding `records` into `datagram`, which has the
/// length [`checked_datagram_len`] returned.
fn put_datagram(
    datagram: &mut [u8],
    header: DatagramHeaderFields<'_>,
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
) {
    let imei = header.imei.as_bytes();
    let after_length = u16::try_from(datagram.len() - DATAGRAM_LENGTH_LEN)
        .expect("`checked_datagram_len` checked the length");
    let imei_len = u16::try_from(imei.len()).expect("the IMEI is shorter than the datagram");

    let mut rest = datagram;
    put(&mut rest, &after_length.to_be_bytes());
    put(&mut rest, &header.packet_id.to_be_bytes());
    put(&mut rest, &[DATAGRAM_NOT_USABLE, header.avl_packet_id]);
    put(&mut rest, &imei_len.to_be_bytes());
    put(&mut rest, imei);
    put_data(&mut rest, codec, records);
    debug_assert!(rest.is_empty(), "the datagram length counted every byte");
}

/// Encodes AVL records into a new UDP datagram.
///
/// See [`encode_avl_datagram_into`] for the layout.
///
/// # Errors
///
/// Returns [`EncodeAvlError`] when a record doesn't fit `codec` or the
/// datagram is too long for its 2-byte length field.
#[cfg(feature = "alloc")]
pub fn encode_avl_datagram(
    header: DatagramHeaderFields<'_>,
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
) -> Result<Vec<u8>, EncodeAvlError> {
    let mut datagram = alloc::vec![0; checked_datagram_len(header, codec, records)?];
    put_datagram(&mut datagram, header, codec, records);
    Ok(datagram)
}

/// Bytes of a UDP datagram before the IMEI: length, packet ID, the "not
/// usable" byte, AVL packet ID, and IMEI length.
const DATAGRAM_HEADER_LEN: usize = DATAGRAM_LENGTH_LEN + 2 + 1 + 1 + 2;

/// Longest datagram: its length field counts the bytes after itself in a
/// `u16`.
const MAX_DATAGRAM_LEN: usize = DATAGRAM_LENGTH_LEN + u16::MAX as usize;

/// Bytes of the AVL data field around the records: codec ID and the two
/// record counts.
const DATA_OVERHEAD: usize = 1 + 1 + 1;

/// Bytes of a variable-length IO element before its value: a 2-byte ID and
/// a 2-byte length.
const VARIABLE_IO_HEADER_LEN: usize = 2 + 2;

/// Returns the length of the AVL data field holding `records`: codec ID,
/// both counts, and the records. Checks every record against `codec`.
///
/// # Errors
///
/// Returns [`EncodeAvlError`] for no records, more than 255, or the first
/// record that doesn't fit `codec`.
fn checked_data_len(
    codec: AvlCodec,
    records: &[AvlRecordFields<'_>],
) -> Result<usize, EncodeAvlError> {
    if records.is_empty() {
        return Err(EncodeAvlError::NoRecords);
    }
    let limit = usize::from(u8::MAX);
    if records.len() > limit {
        return Err(EncodeAvlError::TooManyRecords {
            count: records.len(),
            limit,
        });
    }
    records.iter().try_fold(DATA_OVERHEAD, |len, record| {
        Ok(len + checked_record_len(codec, record)?)
    })
}

/// Returns the length of `record` in `codec`, checking that it fits.
///
/// # Errors
///
/// Returns the [`EncodeAvlError`] for the first field that doesn't fit
/// `codec`.
fn checked_record_len(
    codec: AvlCodec,
    record: &AvlRecordFields<'_>,
) -> Result<usize, EncodeAvlError> {
    match (codec == AvlCodec::Codec16, record.generation_type) {
        (true, None) => return Err(EncodeAvlError::MissingGenerationType),
        (false, Some(_)) => return Err(EncodeAvlError::UnexpectedGenerationType),
        _ => {}
    }
    if let Some(id) = record.event_io_id {
        if u16::from(id) == 0 {
            return Err(EncodeAvlError::ZeroEventIoId);
        }
        check_id(codec.id_len(), id)?;
    }
    if codec != AvlCodec::Codec8Extended && !record.io_bytes.is_empty() {
        return Err(EncodeAvlError::VariableIoNotSupported);
    }

    let groups = [
        ids_len(codec, record.io_u8.iter().map(|&(id, _)| id), 1)?,
        ids_len(codec, record.io_u16.iter().map(|&(id, _)| id), 2)?,
        ids_len(codec, record.io_u32.iter().map(|&(id, _)| id), 4)?,
        ids_len(codec, record.io_u64.iter().map(|&(id, _)| id), 8)?,
    ];
    // Timestamp to "N of Total IO", then the count of each of the four
    // fixed-width groups.
    let mut len = RECORD_HEAD_LEN
        + codec.id_len()
        + usize::from(codec == AvlCodec::Codec16)
        + codec.count_len()
        + 4 * codec.count_len()
        + groups.iter().map(|&(_, len)| len).sum::<usize>();
    // "N of Total IO" counts every element, the variable-length ones
    // included (Codec 8 Extended devices send it so).
    let mut total = groups.iter().map(|&(count, _)| count).sum::<usize>();
    if codec == AvlCodec::Codec8Extended {
        check_count(codec.count_len(), record.io_bytes.len())?;
        len += codec.count_len();
        for &(id, value) in record.io_bytes {
            if u16::try_from(value.len()).is_err() {
                return Err(EncodeAvlError::IoValueTooLong {
                    id,
                    len: value.len(),
                });
            }
            len += VARIABLE_IO_HEADER_LEN + value.len();
        }
        total += record.io_bytes.len();
    }
    check_count(codec.count_len(), total)?;
    Ok(len)
}

/// Returns the number of elements with `value_len`-byte values and their
/// length in `codec`, checking every ID and the count.
///
/// # Errors
///
/// Returns [`EncodeAvlError::IoIdTooWide`] or
/// [`EncodeAvlError::TooManyIoElements`].
fn ids_len(
    codec: AvlCodec,
    ids: impl ExactSizeIterator<Item = IoId>,
    value_len: usize,
) -> Result<(usize, usize), EncodeAvlError> {
    let count = ids.len();
    check_count(codec.count_len(), count)?;
    for id in ids {
        check_id(codec.id_len(), id)?;
    }
    Ok((count, count * (codec.id_len() + value_len)))
}

/// Returns the largest value a field of `len` bytes, one or two, holds.
const fn max_uint(len: usize) -> u16 {
    if len == 1 { u8::MAX as u16 } else { u16::MAX }
}

/// Checks that `id` fits an ID field of `len` bytes.
///
/// # Errors
///
/// Returns [`EncodeAvlError::IoIdTooWide`] with the widest ID the field
/// holds.
fn check_id(len: usize, id: IoId) -> Result<(), EncodeAvlError> {
    let limit = max_uint(len);
    if u16::from(id) <= limit {
        Ok(())
    } else {
        Err(EncodeAvlError::IoIdTooWide { id, limit })
    }
}

/// Checks that `count` fits a count field of `len` bytes.
///
/// # Errors
///
/// Returns [`EncodeAvlError::TooManyIoElements`] with the largest count the
/// field holds.
fn check_count(len: usize, count: usize) -> Result<(), EncodeAvlError> {
    let limit = usize::from(max_uint(len));
    if count <= limit {
        Ok(())
    } else {
        Err(EncodeAvlError::TooManyIoElements { count, limit })
    }
}

/// Writes `value` big-endian in a field of `len` bytes, one or two.
///
/// # Panics
///
/// Panics if `value` doesn't fit the field: [`checked_record_len`] checks every ID
/// and count before anything is written.
fn put_uint(out: &mut &mut [u8], len: usize, value: u16) {
    if len == 1 {
        put(
            out,
            &[u8::try_from(value).expect("`checked_record_len` checked the width")],
        );
    } else {
        put(out, &value.to_be_bytes());
    }
}

/// Writes the count of a group whose size was checked to fit.
fn put_count(out: &mut &mut [u8], codec: AvlCodec, count: usize) {
    let count = u16::try_from(count).expect("`checked_record_len` checked the count");
    put_uint(out, codec.count_len(), count);
}

/// Writes the AVL data field: codec ID, count, records, count.
fn put_data(out: &mut &mut [u8], codec: AvlCodec, records: &[AvlRecordFields<'_>]) {
    let count = u8::try_from(records.len()).expect("`checked_data_len` checked the count");
    put(out, &[u8::from(codec), count]);
    for record in records {
        put_record(out, codec, record);
    }
    put(out, &[count]);
}

/// Writes one record checked by [`checked_record_len`].
fn put_record(out: &mut &mut [u8], codec: AvlCodec, record: &AvlRecordFields<'_>) {
    put(out, &u64::from(record.timestamp).to_be_bytes());
    put(out, &[u8::from(record.priority)]);
    put(out, &record.gps.to_bytes());
    put_uint(out, codec.id_len(), record.event_io_id.map_or(0, u16::from));
    if let Some(generation_type) = record.generation_type {
        put(out, &[u8::from(generation_type)]);
    }
    let variable = if codec == AvlCodec::Codec8Extended {
        record.io_bytes.len()
    } else {
        0
    };
    put_count(
        out,
        codec,
        record.io_u8.len()
            + record.io_u16.len()
            + record.io_u32.len()
            + record.io_u64.len()
            + variable,
    );

    put_count(out, codec, record.io_u8.len());
    for &(id, value) in record.io_u8 {
        put_uint(out, codec.id_len(), u16::from(id));
        put(out, &[value]);
    }
    put_count(out, codec, record.io_u16.len());
    for &(id, value) in record.io_u16 {
        put_uint(out, codec.id_len(), u16::from(id));
        put(out, &value.to_be_bytes());
    }
    put_count(out, codec, record.io_u32.len());
    for &(id, value) in record.io_u32 {
        put_uint(out, codec.id_len(), u16::from(id));
        put(out, &value.to_be_bytes());
    }
    put_count(out, codec, record.io_u64.len());
    for &(id, value) in record.io_u64 {
        put_uint(out, codec.id_len(), u16::from(id));
        put(out, &value.to_be_bytes());
    }
    if codec == AvlCodec::Codec8Extended {
        put_count(out, codec, record.io_bytes.len());
        for &(id, value) in record.io_bytes {
            let len = u16::try_from(value.len()).expect("`checked_record_len` checked the length");
            put(out, &u16::from(id).to_be_bytes());
            put(out, &len.to_be_bytes());
            put(out, value);
        }
    }
}

/// The error returned when encoding AVL records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeAvlError {
    /// There are no records.
    NoRecords,
    /// There are more records than the one-byte counts can count.
    TooManyRecords {
        /// Number of records given.
        count: usize,
        /// Largest number of records in a packet.
        limit: usize,
    },
    /// An IO ID or event IO ID is wider than the codec's ID field: Codec 8
    /// IDs are one byte.
    IoIdTooWide {
        /// The ID that doesn't fit.
        id: IoId,
        /// Largest ID the codec holds.
        limit: u16,
    },
    /// The event IO ID is 0, which a record sends for "not eventual": leave
    /// it unset instead.
    ZeroEventIoId,
    /// The codec is Codec 16, whose records carry a generation type, and
    /// none was set.
    MissingGenerationType,
    /// A generation type was set, but only Codec 16 carries one.
    UnexpectedGenerationType,
    /// Variable-length IO elements were set, but only Codec 8 Extended
    /// carries them.
    VariableIoNotSupported,
    /// A group of IO elements, or the total, is larger than the codec's
    /// count field: Codec 8 and 16 counts are one byte.
    TooManyIoElements {
        /// Number of elements.
        count: usize,
        /// Largest count the codec holds.
        limit: usize,
    },
    /// A variable-length value is longer than its 2-byte length field.
    IoValueTooLong {
        /// ID of the element.
        id: IoId,
        /// Length of its value.
        len: usize,
    },
    /// The frame is longer than the decoders accept (1280 bytes for Codec 8
    /// and Codec 8 Extended, 65,535 for Codec 16), or the datagram is longer
    /// than its length field can declare (65,537 bytes).
    TooLong {
        /// Frame or datagram length.
        len: usize,
        /// Largest length.
        limit: usize,
    },
    /// The output buffer is shorter than the frame or datagram.
    BufferTooSmall {
        /// Frame or datagram length.
        needed: usize,
    },
}

impl fmt::Display for EncodeAvlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRecords => f.write_str("no AVL record to encode"),
            Self::TooManyRecords { count, limit } => {
                write!(f, "{count} AVL records are over the limit {limit}")
            }
            Self::IoIdTooWide { id, limit } => write!(
                f,
                "IO ID {} is wider than the codec's limit {limit}",
                u16::from(*id)
            ),
            Self::ZeroEventIoId => f.write_str("event IO ID 0 means no event; leave it unset"),
            Self::MissingGenerationType => f.write_str("Codec 16 record has no generation type"),
            Self::UnexpectedGenerationType => {
                f.write_str("only Codec 16 records carry a generation type")
            }
            Self::VariableIoNotSupported => {
                f.write_str("only Codec 8 Extended records carry variable-length IO elements")
            }
            Self::TooManyIoElements { count, limit } => {
                write!(f, "{count} IO elements are over the codec's limit {limit}")
            }
            Self::IoValueTooLong { id, len } => write!(
                f,
                "value of IO element {} is {len} bytes, over the limit {}",
                u16::from(*id),
                u16::MAX
            ),
            Self::TooLong { len, limit } => {
                write!(
                    f,
                    "AVL frame or datagram length {len} is over the limit {limit}"
                )
            }
            Self::BufferTooSmall { needed } => {
                write!(
                    f,
                    "output buffer is shorter than the {needed} bytes to write"
                )
            }
        }
    }
}

impl core::error::Error for EncodeAvlError {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::decoder::{MAX_CODEC8_FRAME_LEN, take_datagram, take_frame};
    use crate::fixtures::{CODEC8_EXTENDED, CODEC16, UDP_CODEC8, bytes};
    use crate::protocol::{AvlRecordView, FrameView, IoValueView};

    const NO_FIX: GpsElement = GpsElement {
        longitude_raw: 0,
        latitude_raw: 0,
        altitude_meters: 0,
        angle_degrees: 0,
        satellites: 0,
        speed_kph: 0,
    };

    fn frame(codec: AvlCodec, records: &[AvlRecordFields<'_>]) -> Vec<u8> {
        let mut out = [0; MAX_CODEC8_FRAME_LEN];
        let len = encode_avl_frame_into(codec, records, &mut out).unwrap();
        out[..len].to_vec()
    }

    fn error(codec: AvlCodec, record: AvlRecordFields<'_>) -> EncodeAvlError {
        encode_avl_frame_into(codec, &[record], &mut [0; MAX_CODEC8_FRAME_LEN]).unwrap_err()
    }

    fn at(millis: u64) -> AvlTimestamp {
        AvlTimestamp::from(millis)
    }

    fn id(value: u16) -> IoId {
        IoId::from(value)
    }

    // Examples from https://wiki.teltonika-gps.com/view/Codec (accessed
    // 2026-09-24).

    #[test]
    fn matches_the_wiki_codec8_extended_example() {
        // "Codec 8 Extended > Codec 8 Extended protocol sending over TCP".
        let io_u8 = [(id(0x0001), 1)];
        let io_u16 = [(id(0x0011), 0x001d)];
        let io_u32 = [(id(0x0010), 0x015e_2c88)];
        let io_u64 = [(id(0x000b), 0x3544_c87a), (id(0x000e), 0x1dd7_e06a)];
        let record = AvlRecordFields::new(at(0x016b_412c_ee00), Priority::High, NO_FIX)
            .with_event_io_id(id(1))
            .with_io_u8(&io_u8)
            .with_io_u16(&io_u16)
            .with_io_u32(&io_u32)
            .with_io_u64(&io_u64);
        assert_eq!(
            frame(AvlCodec::Codec8Extended, &[record]),
            bytes(CODEC8_EXTENDED)
        );
    }

    #[test]
    fn matches_the_wiki_codec16_example() {
        // "Codec 16 > Codec 16 protocol sending over TCP".
        let io_u8 = [(id(0x0001), 0), (id(0x0003), 0)];
        let io_u16 = [(id(0x000b), 0x0027), (id(0x0042), 0x563a)];
        let io_u16_second = [(id(0x000b), 0x0026), (id(0x0042), 0x563a)];
        let record = |millis, io_u16| {
            AvlRecordFields::new(at(millis), Priority::Low, NO_FIX)
                .with_event_io_id(id(0x000b))
                .with_generation_type(GenerationType::OnChange)
                .with_io_u8(&io_u8)
                .with_io_u16(io_u16)
        };
        let records = [
            record(0x016b_dbc7_8330, &io_u16[..]),
            record(0x016b_dbc7_8718, &io_u16_second[..]),
        ];
        assert_eq!(frame(AvlCodec::Codec16, &records), bytes(CODEC16));
    }

    #[test]
    fn matches_the_wiki_udp_example() {
        // "Codec 8 > Codec8 protocol sending over UDP > Example".
        let io_u8 = [(id(0x15), 3), (id(0x01), 1)];
        let io_u16 = [(id(0x42), 0x5dbc)];
        let record = AvlRecordFields::new(at(0x016b_4f81_5b30), Priority::High, NO_FIX)
            .with_event_io_id(id(1))
            .with_io_u8(&io_u8)
            .with_io_u16(&io_u16);
        let header = DatagramHeaderFields {
            packet_id: 0xcafe,
            avl_packet_id: 0x05,
            imei: ImeiView::try_from("352093086403655").unwrap(),
        };
        let mut out = [0; 128];
        let len = encode_avl_datagram_into(header, AvlCodec::Codec8, &[record], &mut out).unwrap();
        assert_eq!(out[..len], bytes(UDP_CODEC8));
        assert!(take_datagram(&mut &out[..len]).is_ok());
    }

    fn decoded_record(bytes: &[u8]) -> AvlRecordView<'_> {
        let Ok(FrameView::Avl(packet)) = take_frame(&mut &bytes[..]) else {
            panic!("expected an AVL frame");
        };
        packet.records().next().unwrap()
    }

    #[test]
    fn variable_io_decodes_back_and_counts_in_n() {
        let io_bytes: [(IoId, &[u8]); 2] = [(id(0x0101), b"ab"), (id(0x0102), b"")];
        let io_u8 = [(id(0x0200), 7)];
        let record = AvlRecordFields::new(at(1), Priority::Panic, NO_FIX)
            .with_io_u8(&io_u8)
            .with_io_bytes(&io_bytes);
        let bytes = frame(AvlCodec::Codec8Extended, &[record]);
        let decoded = decoded_record(&bytes);

        assert_eq!(decoded.event_io_id(), None);
        let elements: Vec<_> = decoded
            .io_elements()
            .map(|element| (u16::from(element.id()), element.value()))
            .collect();
        assert_eq!(
            elements,
            [
                (0x0200, IoValueView::U8(7)),
                (0x0101, IoValueView::Bytes(b"ab")),
                (0x0102, IoValueView::Bytes(b"")),
            ]
        );
    }

    #[test]
    fn rejects_fields_the_codec_cant_carry() {
        let wide = [(id(0x0100), 1)];
        let base = AvlRecordFields::new(at(0), Priority::Low, NO_FIX);
        assert_eq!(
            error(AvlCodec::Codec8, base.with_io_u8(&wide)),
            EncodeAvlError::IoIdTooWide {
                id: id(0x0100),
                limit: 0xff
            }
        );
        assert_eq!(
            error(AvlCodec::Codec8, base.with_event_io_id(id(0x0100))),
            EncodeAvlError::IoIdTooWide {
                id: id(0x0100),
                limit: 0xff
            }
        );
        assert_eq!(
            error(AvlCodec::Codec8Extended, base.with_event_io_id(id(0))),
            EncodeAvlError::ZeroEventIoId
        );
        assert_eq!(
            error(AvlCodec::Codec16, base),
            EncodeAvlError::MissingGenerationType
        );
        assert_eq!(
            error(
                AvlCodec::Codec8,
                base.with_generation_type(GenerationType::Eventual)
            ),
            EncodeAvlError::UnexpectedGenerationType
        );
        let bytes: [(IoId, &[u8]); 1] = [(id(1), b"x")];
        let codec16 = base.with_generation_type(GenerationType::Eventual);
        assert_eq!(
            error(AvlCodec::Codec16, codec16.with_io_bytes(&bytes)),
            EncodeAvlError::VariableIoNotSupported
        );
        let many = [(id(1), 0); 256];
        assert_eq!(
            error(AvlCodec::Codec8, base.with_io_u8(&many)),
            EncodeAvlError::TooManyIoElements {
                count: 256,
                limit: 255
            }
        );
    }

    #[test]
    fn rejects_a_total_over_the_count_width() {
        // 200 + 100 elements: each group fits a byte, the total doesn't.
        let io_u8 = [(id(1), 0); 200];
        let io_u16 = [(id(1), 0); 100];
        let record = AvlRecordFields::new(at(0), Priority::Low, NO_FIX)
            .with_io_u8(&io_u8)
            .with_io_u16(&io_u16);
        assert_eq!(
            error(AvlCodec::Codec8, record),
            EncodeAvlError::TooManyIoElements {
                count: 300,
                limit: 255
            }
        );
    }

    #[test]
    fn rejects_packets_that_cant_form_a_frame() {
        let record = AvlRecordFields::new(at(0), Priority::Low, NO_FIX);
        let mut out = [0; MAX_CODEC8_FRAME_LEN];
        assert_eq!(
            encode_avl_frame_into(AvlCodec::Codec8, &[], &mut out),
            Err(EncodeAvlError::NoRecords)
        );
        assert_eq!(
            encode_avl_frame_into(AvlCodec::Codec8, &[record; 256], &mut out),
            Err(EncodeAvlError::TooManyRecords {
                count: 256,
                limit: 255
            })
        );
        // A Codec 8 record without IO elements is 30 bytes: 43 of them make
        // a 1305-byte frame.
        assert_eq!(
            encode_avl_frame_into(AvlCodec::Codec8, &[record; 43], &mut out),
            Err(EncodeAvlError::TooLong {
                len: 12 + 3 + 43 * 30,
                limit: 1280
            })
        );
        // Codec 16 has no 1280-byte limit: 255 records of 32 bytes decode
        // back.
        let periodical = record.with_generation_type(GenerationType::Periodical);
        let long = encode_avl_frame(AvlCodec::Codec16, &[periodical; 255]).unwrap();
        assert_eq!(long.len(), 12 + 3 + 255 * 32);
        let FrameView::Avl(packet) = take_frame(&mut &long[..]).unwrap() else {
            panic!("expected AVL data");
        };
        assert_eq!(packet.records().len(), 255);
        let mut short = [0xaa; 44];
        assert_eq!(
            encode_avl_frame_into(AvlCodec::Codec8, &[record], &mut short),
            Err(EncodeAvlError::BufferTooSmall { needed: 45 })
        );
        assert_eq!(short, [0xaa; 44]);
    }
}
