use std::num::NonZeroUsize;

use crate::checksum::crc16;
use crate::protocol_impl::{
    AvlCodec, AvlPacket, AvlRecord, AvlTimestamp, Codec12Message, Codec12Packet, CountStatus,
    DecodeError, Decoded, FatalReason, Frame, GenerationType, GpsElement, Imei, IoElement, IoId,
    IoValue, Priority, RejectionReason, TcpLimits, UdpDatagram, UdpDecodeError, UdpLimits,
};

const IMEI_LENGTH: usize = 15;
const TCP_PREFIX_LENGTH: usize = 8;
const TCP_CRC_LENGTH: usize = 4;
const MINIMUM_DATA_LENGTH: usize = 3;

/// Decodes the length-prefixed ASCII IMEI sent at the start of a TCP session.
///
/// The result owns the validated 15 decimal digits. Bytes after the handshake
/// remain untouched and are excluded from [`Decoded::consumed`].
///
/// # Errors
///
/// Returns [`DecodeError::Fatal`] immediately when the two-byte prefix declares
/// a length other than 15. Returns [`DecodeError::Incomplete`] until all 15
/// bytes are present and [`DecodeError::Rejected`] for a complete handshake
/// containing a non-decimal byte.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::decode_imei;
///
/// let decoded = decode_imei(b"\x00\x0f356307042441013next").unwrap();
/// assert_eq!(decoded.value.as_str(), "356307042441013");
/// assert_eq!(decoded.consumed, 17);
/// ```
pub fn decode_imei(input: &[u8]) -> Result<Decoded<Imei>, DecodeError> {
    let mut cursor = SliceCursor::new(input);
    let length = usize::from(cursor.u16()?);
    if length != IMEI_LENGTH {
        return Err(DecodeError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidImeiLength {
                declared: length,
                expected: IMEI_LENGTH,
            },
        });
    }
    let digits = *cursor.array::<IMEI_LENGTH>()?;
    let value = Imei::new(digits).map_err(|_| DecodeError::Rejected {
        consumed: cursor.position(),
        offset: 2,
        reason: RejectionReason::InvalidImei,
    })?;
    Ok(Decoded {
        value,
        consumed: cursor.position(),
    })
}

/// Decodes one TCP AVL or Codec 12 frame using [`TcpLimits::default`].
///
/// The decoder validates the preamble, declared length, codec-specific layout,
/// duplicate counts, and CRC before returning an owned [`Frame`]. It stops at
/// the first complete frame when `input` also contains the next frame.
///
/// # Errors
///
/// See [`DecodeError`] for the buffering and recovery contract. In particular,
/// retain all input on [`DecodeError::Incomplete`], consume exactly the reported
/// bytes on [`DecodeError::Rejected`], and reset or close the transport after
/// [`DecodeError::Fatal`] unless you have an external resynchronization rule.
///
/// # Examples
///
/// ```
/// use nom_teltonika::{encoder::encode_codec12_command, decoder::decode_tcp_frame};
///
/// let bytes = encode_codec12_command(b"getinfo").unwrap();
/// let decoded = decode_tcp_frame(&bytes).unwrap();
/// assert_eq!(decoded.consumed, bytes.len());
/// ```
pub fn decode_tcp_frame(input: &[u8]) -> Result<Decoded<Frame>, DecodeError> {
    decode_tcp_frame_with_limits(input, TcpLimits::default())
}

/// Parses one TCP frame with caller-provided wire-size limits.
///
/// Use this variant at trust boundaries where limits differ from the defaults.
/// A declared size above the codec-specific limit fails as soon as the header
/// and codec ID are available, before the decoder waits for or allocates the
/// declared payload.
///
/// # Errors
///
/// Returns the same [`DecodeError`] variants as [`decode_tcp_frame`], including a
/// fatal [`crate::decoder::FatalReason::FrameTooLarge`] when the declared complete
/// wire size exceeds `limits`.
pub fn decode_tcp_frame_with_limits(
    input: &[u8],
    limits: TcpLimits,
) -> Result<Decoded<Frame>, DecodeError> {
    let result = decode_tcp_frame_inner(input, limits);
    trace_decode_result("tcp", &result);
    result
}

fn decode_tcp_frame_inner(input: &[u8], limits: TcpLimits) -> Result<Decoded<Frame>, DecodeError> {
    let mut cursor = SliceCursor::new(input);
    if cursor.array::<4>()? != &[0; 4] {
        return Err(DecodeError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidPreamble,
        });
    }
    let data_length = cursor.u32()? as usize;
    let total = data_length
        .checked_add(TCP_PREFIX_LENGTH + TCP_CRC_LENGTH)
        .ok_or(DecodeError::Fatal {
            offset: 4,
            reason: FatalReason::LengthOverflow,
        })?;
    let codec_id = cursor.peek_u8()?;
    let limit = if codec_id == 0x0c {
        limits.max_codec12_frame_bytes()
    } else {
        limits.max_avl_frame_bytes()
    };
    if total > limit {
        return Err(DecodeError::Fatal {
            offset: 4,
            reason: FatalReason::FrameTooLarge {
                declared: total,
                limit,
            },
        });
    }
    cursor.ensure(total - TCP_PREFIX_LENGTH)?;
    if data_length < MINIMUM_DATA_LENGTH {
        return reject(total, 4, RejectionReason::InvalidPayloadLength);
    }

    let data = cursor.take(data_length)?;
    let received_crc = cursor.u32()?;
    let expected_crc = crc16(data);
    if received_crc != u32::from(expected_crc) {
        return reject(
            total,
            total - 4,
            RejectionReason::CrcMismatch {
                expected: expected_crc,
                received: received_crc,
            },
        );
    }

    let value = match codec_id {
        0x08 | 0x8e | 0x10 => Frame::Avl(
            decode_avl_packet(data).map_err(|error| error.into_decode(total, TCP_PREFIX_LENGTH))?,
        ),
        0x0c => Frame::Codec12(
            decode_codec12_packet(data)
                .map_err(|error| error.into_decode(total, TCP_PREFIX_LENGTH))?,
        ),
        codec_id => {
            return reject(
                total,
                TCP_PREFIX_LENGTH,
                RejectionReason::UnsupportedCodec { codec_id },
            );
        }
    };
    Ok(Decoded {
        value,
        consumed: total,
    })
}

/// Decodes exactly one UDP AVL datagram using [`UdpLimits::default`].
///
/// This slice decoder is useful with custom socket code. Unlike
/// [`crate::udp::TeltonikaUdpSocket`], it deliberately permits bytes after the
/// first declared datagram and reports where they begin through
/// [`Decoded::consumed`].
///
/// # Errors
///
/// Returns [`DecodeError::Incomplete`] for a truncated declared datagram,
/// [`DecodeError::Rejected`] for a safely delimited invalid payload, and
/// [`DecodeError::Fatal`] when framing cannot be trusted.
pub fn decode_udp_datagram(input: &[u8]) -> Result<UdpDatagram, UdpDecodeError> {
    decode_udp_datagram_with_limits(input, UdpLimits::default())
}

/// Parses one UDP AVL datagram with caller-provided wire-size limits.
///
/// The limit counts the complete datagram, including its two-byte length. Use
/// [`crate::udp::TeltonikaUdpSocket`] when you also need truncation detection and
/// source-address preservation from a socket.
///
/// # Errors
///
/// Returns the same [`DecodeError`] variants as [`decode_udp_datagram`], including
/// a fatal [`crate::decoder::FatalReason::DatagramTooLarge`] when the declared
/// complete wire size exceeds `limits`.
pub fn decode_udp_datagram_with_limits(
    input: &[u8],
    limits: UdpLimits,
) -> Result<UdpDatagram, UdpDecodeError> {
    let result = decode_udp_datagram_inner(input, limits);
    trace_udp_result(&result);
    result
}

fn decode_udp_datagram_inner(
    input: &[u8],
    limits: UdpLimits,
) -> Result<UdpDatagram, UdpDecodeError> {
    if input.len() < 2 {
        return Err(UdpDecodeError::TruncatedHeader {
            actual: input.len(),
        });
    }
    let mut cursor = SliceCursor::new(input);
    let payload_length = usize::from(cursor.u16()?);
    let total = payload_length + 2;
    if total > limits.max_datagram_bytes() {
        return Err(UdpDecodeError::DatagramTooLarge {
            declared: total,
            limit: limits.max_datagram_bytes(),
        });
    }
    if input.len() != total {
        return Err(UdpDecodeError::LengthMismatch {
            declared: total,
            actual: input.len(),
        });
    }
    if total < 23 {
        return udp_invalid(2, RejectionReason::InvalidPayloadLength);
    }
    let channel_packet_id = cursor.u16()?;
    let channel_offset = cursor.position();
    let channel = cursor.u8()?;
    if channel != 1 {
        return udp_invalid(
            channel_offset,
            RejectionReason::InvalidChannel { value: channel },
        );
    }
    let avl_packet_id = cursor.u8()?;
    let imei_length_offset = cursor.position();
    let imei_length = usize::from(cursor.u16()?);
    if imei_length != IMEI_LENGTH {
        return udp_invalid(imei_length_offset, RejectionReason::InvalidImei);
    }
    let imei_offset = cursor.position();
    let imei_digits = *cursor.array::<IMEI_LENGTH>()?;
    let imei = Imei::new(imei_digits).map_err(|_| UdpDecodeError::Invalid {
        offset: imei_offset,
        reason: RejectionReason::InvalidImei,
    })?;
    let packet_offset = cursor.position();
    let packet = decode_avl_packet(cursor.take(cursor.remaining())?)
        .map_err(|error| error.into_udp(packet_offset))?;
    Ok(UdpDatagram::from_parts(
        channel_packet_id,
        avl_packet_id,
        imei,
        packet,
    ))
}

fn udp_invalid<T>(offset: usize, reason: RejectionReason) -> Result<T, UdpDecodeError> {
    Err(UdpDecodeError::Invalid { offset, reason })
}

fn decode_avl_packet(data: &[u8]) -> Result<AvlPacket, PacketError> {
    let mut cursor = SliceCursor::new(data);
    let codec_offset = cursor.position();
    let codec_id = cursor.u8()?;
    let codec = match codec_id {
        0x08 => AvlCodec::Codec8,
        0x8e => AvlCodec::Codec8Extended,
        0x10 => AvlCodec::Codec16,
        codec_id => {
            return Err(PacketError::at(
                codec_offset,
                RejectionReason::UnsupportedCodec { codec_id },
            ));
        }
    };
    let record_count_offset = cursor.position();
    let record_count = cursor.u8()?;
    if record_count == 0 {
        return Err(PacketError::at(
            record_count_offset,
            RejectionReason::EmptyAvlPacket,
        ));
    }
    let mut records = Vec::with_capacity(usize::from(record_count));
    for _ in 0..record_count {
        records.push(decode_record(&mut cursor, codec)?);
    }
    let second_count_offset = cursor.position();
    let second_count = cursor.u8()?;
    if record_count != second_count {
        return Err(PacketError::at(
            second_count_offset,
            RejectionReason::RecordCountMismatch {
                first: record_count,
                second: second_count,
            },
        ));
    }
    if cursor.remaining() != 0 {
        return Err(PacketError::at(
            cursor.position(),
            RejectionReason::TrailingData,
        ));
    }
    Ok(AvlPacket::from_parts(codec, records))
}

fn decode_codec12_packet(data: &[u8]) -> Result<Codec12Packet, PacketError> {
    let mut cursor = SliceCursor::new(data);
    cursor.u8()?;
    let first_count_offset = cursor.position();
    let first_count = cursor.u8()?;
    let mut type_id = None;
    let mut payloads = Vec::new();
    while cursor.remaining() > 1 {
        if payloads.len() == usize::from(u8::MAX) {
            return Err(PacketError::at(
                cursor.position(),
                RejectionReason::TooManyCodec12Messages {
                    actual: payloads.len() + 1,
                    maximum: usize::from(u8::MAX),
                },
            ));
        }
        let type_offset = cursor.position();
        let current_type = cursor.u8()?;
        if let Some(expected) = type_id.filter(|expected| *expected != current_type) {
            return Err(PacketError::at(
                type_offset,
                RejectionReason::Codec12TypeMismatch {
                    expected,
                    actual: current_type,
                },
            ));
        }
        type_id.get_or_insert(current_type);
        let length = cursor.u32()? as usize;
        let payload = cursor.take(length)?;
        payloads.push(payload.to_vec());
    }
    if payloads.is_empty() {
        return Err(PacketError::at(
            first_count_offset,
            RejectionReason::EmptyCodec12Batch,
        ));
    }
    let second_count = cursor.u8()?;
    if cursor.remaining() != 0 {
        return Err(PacketError::at(
            cursor.position(),
            RejectionReason::TrailingData,
        ));
    }
    let count_status = if first_count == second_count {
        CountStatus::Matched
    } else {
        CountStatus::Mismatched {
            first: first_count,
            second: second_count,
        }
    };
    let decoded_count = payloads.len();
    let counts_match =
        usize::from(first_count) == decoded_count && usize::from(second_count) == decoded_count;
    let type_id = type_id.expect("non-empty Codec 12 batch establishes a type");
    let message = match type_id {
        0x05 => Codec12Message::Command(payloads),
        0x06 => Codec12Message::Response(payloads),
        type_id => Codec12Message::Other { type_id, payloads },
    };
    Ok(Codec12Packet::from_parts(
        message,
        count_status,
        counts_match,
    ))
}

fn decode_record(cursor: &mut SliceCursor<'_>, codec: AvlCodec) -> Result<AvlRecord, PacketError> {
    let timestamp = AvlTimestamp::from_unix_millis(cursor.u64()?);
    let priority = match cursor.u8()? {
        0 => Priority::Low,
        1 => Priority::High,
        2 => Priority::Panic,
        value => {
            return Err(PacketError::at(
                cursor.position(),
                RejectionReason::InvalidPriority { value },
            ));
        }
    };
    let gps = GpsElement {
        longitude_raw: cursor.i32()?,
        latitude_raw: cursor.i32()?,
        altitude_meters: cursor.u16()?,
        angle_degrees: cursor.u16()?,
        satellites: cursor.u8()?,
        speed_kph: cursor.u16()?,
    };
    let event_id = match codec {
        AvlCodec::Codec8 => u16::from(cursor.u8()?),
        AvlCodec::Codec8Extended | AvlCodec::Codec16 => cursor.u16()?,
    };
    let generation_type = if codec == AvlCodec::Codec16 {
        Some(match cursor.u8()? {
            0 => GenerationType::OnExit,
            1 => GenerationType::OnEntrance,
            2 => GenerationType::OnBoth,
            3 => GenerationType::Reserved,
            4 => GenerationType::Hysteresis,
            5 => GenerationType::OnChange,
            6 => GenerationType::Eventual,
            7 => GenerationType::Periodical,
            value => {
                return Err(PacketError::at(
                    cursor.position(),
                    RejectionReason::InvalidGenerationType { value },
                ));
            }
        })
    } else {
        None
    };
    let declared_count = read_count(cursor, codec)?;
    let mut decoded = 0u16;
    let mut elements = Vec::new();
    for width in [1usize, 2, 4, 8] {
        let count = read_count(cursor, codec)?;
        decoded = decoded.checked_add(count).ok_or_else(|| {
            PacketError::at(cursor.position(), RejectionReason::InvalidPayloadLength)
        })?;
        for _ in 0..count {
            let id = read_id(cursor, codec)?;
            let value = match width {
                1 => IoValue::U8(cursor.u8()?),
                2 => IoValue::U16(cursor.u16()?),
                4 => IoValue::U32(cursor.u32()?),
                8 => IoValue::U64(cursor.u64()?),
                _ => unreachable!(),
            };
            elements.push(IoElement {
                id: IoId::new(id),
                value,
            });
        }
    }
    if codec == AvlCodec::Codec8Extended {
        let count = read_count(cursor, codec)?;
        decoded = decoded.checked_add(count).ok_or_else(|| {
            PacketError::at(cursor.position(), RejectionReason::InvalidPayloadLength)
        })?;
        for _ in 0..count {
            let id = cursor.u16()?;
            let length = usize::from(cursor.u16()?);
            let value = cursor.take(length)?;
            elements.push(IoElement {
                id: IoId::new(id),
                value: IoValue::Bytes(value.to_vec()),
            });
        }
    }
    if declared_count != decoded {
        return Err(PacketError::at(
            cursor.position(),
            RejectionReason::IoCountMismatch {
                declared: declared_count,
                decoded,
            },
        ));
    }
    Ok(AvlRecord {
        timestamp,
        priority,
        gps,
        event_io_id: (event_id != 0).then(|| IoId::new(event_id)),
        generation_type,
        io_elements: elements,
    })
}

fn read_count(cursor: &mut SliceCursor<'_>, codec: AvlCodec) -> Result<u16, PacketError> {
    match codec {
        AvlCodec::Codec8 | AvlCodec::Codec16 => Ok(u16::from(cursor.u8()?)),
        AvlCodec::Codec8Extended => Ok(cursor.u16()?),
    }
}

fn read_id(cursor: &mut SliceCursor<'_>, codec: AvlCodec) -> Result<u16, PacketError> {
    match codec {
        AvlCodec::Codec8 => Ok(u16::from(cursor.u8()?)),
        AvlCodec::Codec8Extended | AvlCodec::Codec16 => Ok(cursor.u16()?),
    }
}

struct SliceCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    const fn position(&self) -> usize {
        self.position
    }
    const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn ensure(&self, length: usize) -> Result<(), UnexpectedEnd> {
        if self.remaining() >= length {
            return Ok(());
        }
        Err(UnexpectedEnd {
            offset: self.position,
            needed: NonZeroUsize::new(length - self.remaining())
                .expect("insufficient input has a positive deficit"),
        })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], UnexpectedEnd> {
        self.ensure(length)?;
        let start = self.position;
        let end = start + length;
        let value = &self.input[start..end];
        self.position = end;
        Ok(value)
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<&'a [u8; LENGTH], UnexpectedEnd> {
        Ok(self
            .take(LENGTH)?
            .try_into()
            .expect("take returns the requested number of bytes"))
    }
    fn peek_u8(&self) -> Result<u8, UnexpectedEnd> {
        self.ensure(1)?;
        Ok(self.input[self.position])
    }
    fn u8(&mut self) -> Result<u8, UnexpectedEnd> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, UnexpectedEnd> {
        Ok(u16::from_be_bytes(*self.array()?))
    }
    fn u32(&mut self) -> Result<u32, UnexpectedEnd> {
        Ok(u32::from_be_bytes(*self.array()?))
    }
    fn u64(&mut self) -> Result<u64, UnexpectedEnd> {
        Ok(u64::from_be_bytes(*self.array()?))
    }
    fn i32(&mut self) -> Result<i32, UnexpectedEnd> {
        Ok(i32::from_be_bytes(*self.array()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnexpectedEnd {
    offset: usize,
    needed: NonZeroUsize,
}

impl From<UnexpectedEnd> for DecodeError {
    fn from(error: UnexpectedEnd) -> Self {
        Self::Incomplete {
            needed: error.needed,
        }
    }
}

impl From<UnexpectedEnd> for UdpDecodeError {
    fn from(error: UnexpectedEnd) -> Self {
        Self::Invalid {
            offset: error.offset,
            reason: RejectionReason::InvalidPayloadLength,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacketError {
    offset: usize,
    reason: RejectionReason,
}

impl PacketError {
    const fn at(offset: usize, reason: RejectionReason) -> Self {
        Self { offset, reason }
    }

    const fn into_decode(self, consumed: usize, base: usize) -> DecodeError {
        rejected(consumed, base + self.offset, self.reason)
    }

    const fn into_udp(self, base: usize) -> UdpDecodeError {
        UdpDecodeError::Invalid {
            offset: base + self.offset,
            reason: self.reason,
        }
    }
}

impl From<UnexpectedEnd> for PacketError {
    fn from(error: UnexpectedEnd) -> Self {
        Self {
            offset: error.offset,
            reason: RejectionReason::InvalidPayloadLength,
        }
    }
}

fn reject<T>(consumed: usize, offset: usize, reason: RejectionReason) -> Result<T, DecodeError> {
    Err(rejected(consumed, offset, reason))
}

const fn rejected(consumed: usize, offset: usize, reason: RejectionReason) -> DecodeError {
    DecodeError::Rejected {
        consumed,
        offset,
        reason,
    }
}

#[cfg(feature = "tracing")]
fn trace_decode_result(transport: &'static str, result: &Result<Decoded<Frame>, DecodeError>) {
    match result {
        Ok(decoded) => tracing::trace!(
            transport,
            outcome = "accepted",
            consumed = decoded.consumed,
            codec_id = decoded.value.codec_id(),
            "decoded protocol frame"
        ),
        Err(DecodeError::Incomplete { needed }) => tracing::trace!(
            transport,
            outcome = "incomplete",
            needed = needed.get(),
            "protocol frame incomplete"
        ),
        Err(DecodeError::Rejected {
            consumed, offset, ..
        }) => tracing::debug!(
            transport,
            outcome = "rejected",
            consumed,
            offset,
            "protocol frame rejected"
        ),
        Err(DecodeError::Fatal { offset, .. }) => tracing::debug!(
            transport,
            outcome = "fatal",
            offset,
            "protocol framing failed"
        ),
    }
}

#[cfg(not(feature = "tracing"))]
fn trace_decode_result(_: &'static str, _: &Result<Decoded<Frame>, DecodeError>) {}

#[cfg(feature = "tracing")]
fn trace_udp_result(result: &Result<UdpDatagram, UdpDecodeError>) {
    match result {
        Ok(datagram) => tracing::trace!(
            transport = "udp",
            outcome = "accepted",
            codec_id = datagram.packet().codec().id(),
            "decoded protocol datagram"
        ),
        Err(UdpDecodeError::TruncatedHeader { actual }) => tracing::debug!(
            transport = "udp",
            outcome = "truncated_header",
            actual,
            "protocol datagram rejected"
        ),
        Err(UdpDecodeError::Invalid { offset, .. }) => tracing::debug!(
            transport = "udp",
            outcome = "invalid",
            offset,
            "protocol datagram rejected"
        ),
        Err(UdpDecodeError::LengthMismatch { declared, actual }) => tracing::debug!(
            transport = "udp",
            outcome = "length_mismatch",
            declared,
            actual,
            "protocol datagram rejected"
        ),
        Err(UdpDecodeError::DatagramTooLarge { declared, limit }) => tracing::debug!(
            transport = "udp",
            outcome = "too_large",
            declared,
            limit,
            "protocol datagram rejected"
        ),
    }
}

#[cfg(not(feature = "tracing"))]
fn trace_udp_result(_: &Result<UdpDatagram, UdpDecodeError>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_cursor_reads_big_endian_values_without_copying_slices() {
        let input = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
        let mut cursor = SliceCursor::new(&input);

        assert_eq!(cursor.u16().unwrap(), 0x1234);
        assert_eq!(cursor.u32().unwrap(), 0x56789abc);
        let tail = cursor.take(1).unwrap();

        assert_eq!(tail, &[0xde]);
        assert!(std::ptr::eq(tail.as_ptr(), input[6..].as_ptr()));
        assert_eq!(cursor.position(), input.len());
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn slice_cursor_reports_exact_need_without_advancing_on_failure() {
        let mut cursor = SliceCursor::new(&[0xaa]);
        assert_eq!(cursor.u8().unwrap(), 0xaa);

        assert_eq!(
            cursor.u32().unwrap_err(),
            UnexpectedEnd {
                offset: 1,
                needed: NonZeroUsize::new(4).unwrap(),
            }
        );
        assert_eq!(cursor.position(), 1);
    }
}
