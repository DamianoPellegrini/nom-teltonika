use std::num::NonZeroUsize;

use crate::checksum::crc16;
use crate::protocol_impl::{
    AvlCodec, AvlPacket, AvlRecord, AvlTimestamp, Codec12Message, Codec12Packet, CountStatus,
    DecodeError, Decoded, FatalReason, Frame, GenerationType, GpsElement, Imei, IoElement, IoId,
    IoValue, Priority, RejectionReason, TcpLimits, UdpDatagram, UdpDecodeError, UdpLimits,
};

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
    require(input.len(), 2)?;
    let (length, remaining) = input.split_at(2);
    let length = usize::from(u16::from_be_bytes(length.try_into().expect("two bytes")));
    if length != 15 {
        return Err(DecodeError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidImeiLength {
                declared: length,
                expected: 15,
            },
        });
    }
    require(remaining.len(), length)?;
    let (digits, remaining) = remaining.split_at(length);
    let consumed = input.len() - remaining.len();
    let digits: [u8; 15] = digits.try_into().map_err(|_| DecodeError::Rejected {
        consumed,
        offset: 0,
        reason: RejectionReason::InvalidImei,
    })?;
    let value = Imei::new(digits).map_err(|_| DecodeError::Rejected {
        consumed,
        offset: 2,
        reason: RejectionReason::InvalidImei,
    })?;
    Ok(Decoded { value, consumed })
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
    require(input.len(), 4)?;
    let (preamble, remaining) = input.split_at(4);
    if preamble != [0; 4] {
        return Err(DecodeError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidPreamble,
        });
    }
    require(remaining.len(), 4)?;
    let (data_length, remaining) = remaining.split_at(4);
    let data_length = u32::from_be_bytes(data_length.try_into().expect("four bytes")) as usize;
    let total = data_length.checked_add(12).ok_or(DecodeError::Fatal {
        offset: 4,
        reason: FatalReason::LengthOverflow,
    })?;
    require(remaining.len(), 1)?;
    let codec_id = remaining[0];
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
    require(remaining.len(), total - 8)?;
    if data_length < 3 {
        return reject(total, 4, RejectionReason::InvalidPayloadLength);
    }

    let (data, remaining) = remaining.split_at(data_length);
    let (received_crc, _) = remaining.split_at(4);
    let received_crc = u32::from_be_bytes(received_crc.try_into().expect("four bytes"));
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
        0x08 | 0x8e | 0x10 => Frame::Avl(decode_avl_packet(data, total, 8)?),
        0x0c => Frame::Codec12(decode_codec12_packet(data, total, 8)?),
        codec_id => return reject(total, 8, RejectionReason::UnsupportedCodec { codec_id }),
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
    let (payload_length, remaining) = input.split_at(2);
    let payload_length = usize::from(u16::from_be_bytes(
        payload_length.try_into().expect("two bytes"),
    ));
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
    let payload = remaining;
    if total < 23 {
        return udp_invalid(2, RejectionReason::InvalidPayloadLength);
    }
    let channel_packet_id = u16::from_be_bytes(payload[..2].try_into().expect("two bytes"));
    if payload[2] != 1 {
        return udp_invalid(4, RejectionReason::InvalidChannel { value: payload[2] });
    }
    let avl_packet_id = payload[3];
    let imei_length = usize::from(u16::from_be_bytes(
        payload[4..6].try_into().expect("two bytes"),
    ));
    if imei_length != 15 {
        return udp_invalid(6, RejectionReason::InvalidImei);
    }
    let imei_digits: [u8; 15] = payload[6..21].try_into().expect("fifteen bytes");
    let imei = Imei::new(imei_digits).map_err(|_| UdpDecodeError::Invalid {
        offset: 8,
        reason: RejectionReason::InvalidImei,
    })?;
    let packet = decode_avl_packet(&payload[21..], total, 23).map_err(|error| match error {
        DecodeError::Rejected { offset, reason, .. } => UdpDecodeError::Invalid { offset, reason },
        DecodeError::Incomplete { .. } | DecodeError::Fatal { .. } => UdpDecodeError::Invalid {
            offset: 23,
            reason: RejectionReason::InvalidPayloadLength,
        },
    })?;
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

fn decode_avl_packet(data: &[u8], consumed: usize, base: usize) -> Result<AvlPacket, DecodeError> {
    let codec = match data.first().copied() {
        Some(0x08) => AvlCodec::Codec8,
        Some(0x8e) => AvlCodec::Codec8Extended,
        Some(0x10) => AvlCodec::Codec16,
        Some(codec_id) => {
            return reject(
                consumed,
                base,
                RejectionReason::UnsupportedCodec { codec_id },
            );
        }
        None => return reject(consumed, base, RejectionReason::InvalidPayloadLength),
    };
    let mut cursor = ByteCursor::new(data);
    cursor
        .skip(1)
        .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
    let record_count = cursor
        .u8()
        .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
    if record_count == 0 {
        return reject(consumed, base + 1, RejectionReason::EmptyAvlPacket);
    }
    let mut records = Vec::with_capacity(usize::from(record_count));
    for _ in 0..record_count {
        records.push(
            decode_record(&mut cursor, codec)
                .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?,
        );
    }
    let second_count = cursor
        .u8()
        .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
    if record_count != second_count {
        return reject(
            consumed,
            base + cursor.position() - 1,
            RejectionReason::RecordCountMismatch {
                first: record_count,
                second: second_count,
            },
        );
    }
    if cursor.remaining() != 0 {
        return reject(
            consumed,
            base + cursor.position(),
            RejectionReason::TrailingData,
        );
    }
    Ok(AvlPacket::from_parts(codec, records))
}

fn decode_codec12_packet(
    data: &[u8],
    consumed: usize,
    base: usize,
) -> Result<Codec12Packet, DecodeError> {
    let mut cursor = ByteCursor::new(data);
    cursor
        .skip(1)
        .map_err(|reason| rejected(consumed, base, reason))?;
    let first_count = cursor
        .u8()
        .map_err(|reason| rejected(consumed, base + 1, reason))?;
    let mut type_id = None;
    let mut payloads = Vec::new();
    while cursor.remaining() > 1 {
        if payloads.len() == usize::from(u8::MAX) {
            return reject(
                consumed,
                base + cursor.position(),
                RejectionReason::TooManyCodec12Messages {
                    actual: payloads.len() + 1,
                    maximum: usize::from(u8::MAX),
                },
            );
        }
        let current_type = cursor
            .u8()
            .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
        if let Some(expected) = type_id.filter(|expected| *expected != current_type) {
            return reject(
                consumed,
                base + cursor.position() - 1,
                RejectionReason::Codec12TypeMismatch {
                    expected,
                    actual: current_type,
                },
            );
        }
        type_id.get_or_insert(current_type);
        let length = cursor
            .u32()
            .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?
            as usize;
        let payload = cursor
            .take(length)
            .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
        payloads.push(payload.to_vec());
    }
    if payloads.is_empty() {
        return reject(consumed, base + 1, RejectionReason::EmptyCodec12Batch);
    }
    let second_count = cursor
        .u8()
        .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
    if cursor.remaining() != 0 {
        return reject(
            consumed,
            base + cursor.position(),
            RejectionReason::TrailingData,
        );
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

fn decode_record(
    cursor: &mut ByteCursor<'_>,
    codec: AvlCodec,
) -> Result<AvlRecord, RejectionReason> {
    let timestamp = AvlTimestamp::from_unix_millis(cursor.u64()?);
    let priority = match cursor.u8()? {
        0 => Priority::Low,
        1 => Priority::High,
        2 => Priority::Panic,
        value => return Err(RejectionReason::InvalidPriority { value }),
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
            value => return Err(RejectionReason::InvalidGenerationType { value }),
        })
    } else {
        None
    };
    let declared_count = read_count(cursor, codec)?;
    let mut decoded = 0u16;
    let mut elements = Vec::new();
    for width in [1usize, 2, 4, 8] {
        let count = read_count(cursor, codec)?;
        decoded = decoded
            .checked_add(count)
            .ok_or(RejectionReason::InvalidPayloadLength)?;
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
        decoded = decoded
            .checked_add(count)
            .ok_or(RejectionReason::InvalidPayloadLength)?;
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
        return Err(RejectionReason::IoCountMismatch {
            declared: declared_count,
            decoded,
        });
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

fn read_count(cursor: &mut ByteCursor<'_>, codec: AvlCodec) -> Result<u16, RejectionReason> {
    match codec {
        AvlCodec::Codec8 | AvlCodec::Codec16 => Ok(u16::from(cursor.u8()?)),
        AvlCodec::Codec8Extended => cursor.u16(),
    }
}

fn read_id(cursor: &mut ByteCursor<'_>, codec: AvlCodec) -> Result<u16, RejectionReason> {
    match codec {
        AvlCodec::Codec8 => Ok(u16::from(cursor.u8()?)),
        AvlCodec::Codec8Extended | AvlCodec::Codec16 => cursor.u16(),
    }
}

#[derive(Clone, Copy)]
struct ByteCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    const fn position(self) -> usize {
        self.position
    }
    const fn remaining(self) -> usize {
        self.input.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RejectionReason> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RejectionReason::InvalidPayloadLength)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(RejectionReason::InvalidPayloadLength)?;
        self.position = end;
        Ok(value)
    }

    fn skip(&mut self, length: usize) -> Result<(), RejectionReason> {
        self.take(length).map(|_| ())
    }
    fn u8(&mut self) -> Result<u8, RejectionReason> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RejectionReason> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, RejectionReason> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, RejectionReason> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
    fn i32(&mut self) -> Result<i32, RejectionReason> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
}

fn require(actual: usize, needed: usize) -> Result<(), DecodeError> {
    if actual >= needed {
        Ok(())
    } else {
        Err(DecodeError::Incomplete {
            needed: NonZeroUsize::new(needed - actual).expect("positive difference"),
        })
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
