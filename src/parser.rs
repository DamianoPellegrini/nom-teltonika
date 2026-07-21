use std::num::NonZeroUsize;

use crate::protocol_impl::{
    AvlCodec, AvlPacket, AvlRecord, AvlTimestamp, Codec12Message, Codec12Packet, CountStatus,
    FatalReason, Frame, GenerationType, GpsElement, Imei, IoElement, IoId, IoValue, Limits,
    ParseError, Parsed, Priority, RejectionReason, UdpDatagram,
};

/// Computes the CRC-16/IBM value used by Teltonika TCP frames.
///
/// Pass exactly the bytes from the codec ID through the second record or
/// command count. The TCP preamble, data length, and four-byte CRC field are
/// outside the checksum coverage.
///
/// # Examples
///
/// ```
/// use nom_teltonika::parser::crc16;
///
/// assert_eq!(crc16(b"123456789"), 0xbb3d);
/// ```
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
    }
    crc
}

/// Parses the length-prefixed ASCII IMEI sent at the start of a TCP session.
///
/// The result owns the validated 15 decimal digits. Bytes after the handshake
/// remain untouched and are excluded from [`Parsed::consumed`].
///
/// # Errors
///
/// Returns [`ParseError::Incomplete`] until the declared handshake is present.
/// A complete handshake is [`ParseError::Rejected`] if its length is not 15 or
/// if it contains a non-decimal byte; its `consumed` field identifies the
/// complete handshake that may be discarded.
///
/// # Examples
///
/// ```
/// use nom_teltonika::parser::parse_imei;
///
/// let parsed = parse_imei(b"\x00\x0f356307042441013next").unwrap();
/// assert_eq!(parsed.value.as_str(), "356307042441013");
/// assert_eq!(parsed.consumed, 17);
/// ```
pub fn parse_imei(input: &[u8]) -> Result<Parsed<Imei>, ParseError> {
    require(input.len(), 2)?;
    let (length, remaining) = input.split_at(2);
    let length = usize::from(u16::from_be_bytes(length.try_into().expect("two bytes")));
    require(remaining.len(), length)?;
    let (digits, remaining) = remaining.split_at(length);
    let consumed = input.len() - remaining.len();
    let digits: [u8; 15] = digits.try_into().map_err(|_| ParseError::Rejected {
        consumed,
        offset: 0,
        reason: RejectionReason::InvalidImei,
    })?;
    let value = Imei::new(digits).map_err(|_| ParseError::Rejected {
        consumed,
        offset: 2,
        reason: RejectionReason::InvalidImei,
    })?;
    Ok(Parsed { value, consumed })
}

/// Parses one TCP AVL or Codec 12 frame using [`Limits::default`].
///
/// The parser validates the preamble, declared length, codec-specific layout,
/// duplicate counts, and CRC before returning an owned [`Frame`]. It stops at
/// the first complete frame when `input` also contains the next frame.
///
/// # Errors
///
/// See [`ParseError`] for the buffering and recovery contract. In particular,
/// retain all input on [`ParseError::Incomplete`], consume exactly the reported
/// bytes on [`ParseError::Rejected`], and reset or close the transport after
/// [`ParseError::Fatal`] unless you have an external resynchronization rule.
///
/// # Examples
///
/// ```
/// use nom_teltonika::{encode::encode_codec12_command, parser::parse_tcp_frame};
///
/// let bytes = encode_codec12_command(b"getinfo");
/// let parsed = parse_tcp_frame(&bytes).unwrap();
/// assert_eq!(parsed.consumed, bytes.len());
/// ```
pub fn parse_tcp_frame(input: &[u8]) -> Result<Parsed<Frame>, ParseError> {
    parse_tcp_frame_with_limits(input, Limits::default())
}

/// Parses one TCP frame with caller-provided wire-size limits.
///
/// Use this variant at trust boundaries where limits differ from the defaults.
/// A declared size above the codec-specific limit fails as soon as the header
/// and codec ID are available, before the parser waits for or allocates the
/// declared payload.
///
/// # Errors
///
/// Returns the same [`ParseError`] variants as [`parse_tcp_frame`], including a
/// fatal [`crate::parser::FatalReason::FrameTooLarge`] when the declared complete
/// wire size exceeds `limits`.
pub fn parse_tcp_frame_with_limits(
    input: &[u8],
    limits: Limits,
) -> Result<Parsed<Frame>, ParseError> {
    let result = parse_tcp_frame_inner(input, limits);
    trace_parse_result("tcp", &result);
    result
}

fn parse_tcp_frame_inner(input: &[u8], limits: Limits) -> Result<Parsed<Frame>, ParseError> {
    require(input.len(), 4)?;
    let (preamble, remaining) = input.split_at(4);
    if preamble != [0; 4] {
        return Err(ParseError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidPreamble,
        });
    }
    require(remaining.len(), 4)?;
    let (data_length, remaining) = remaining.split_at(4);
    let data_length = u32::from_be_bytes(data_length.try_into().expect("four bytes")) as usize;
    let total = data_length.checked_add(12).ok_or(ParseError::Fatal {
        offset: 4,
        reason: FatalReason::LengthOverflow,
    })?;
    require(remaining.len(), 1)?;
    let codec_id = remaining[0];
    let limit = if codec_id == 0x0c {
        limits.max_codec12_wire_bytes
    } else {
        limits.max_avl_wire_bytes
    };
    if total > limit {
        return Err(ParseError::Fatal {
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
        0x08 | 0x8e | 0x10 => Frame::Avl(parse_avl_packet(data, total, 8)?),
        0x0c => Frame::Codec12(parse_codec12_packet(data, total, 8)?),
        codec_id => return reject(total, 8, RejectionReason::UnsupportedCodec { codec_id }),
    };
    Ok(Parsed {
        value,
        consumed: total,
    })
}

/// Parses one UDP AVL datagram using [`Limits::default`].
///
/// This slice parser is useful with custom socket code. Unlike
/// [`crate::udp::TeltonikaUdpSocket`], it deliberately permits bytes after the
/// first declared datagram and reports where they begin through
/// [`Parsed::consumed`].
///
/// # Errors
///
/// Returns [`ParseError::Incomplete`] for a truncated declared datagram,
/// [`ParseError::Rejected`] for a safely delimited invalid payload, and
/// [`ParseError::Fatal`] when framing cannot be trusted.
pub fn parse_udp_datagram(input: &[u8]) -> Result<Parsed<UdpDatagram>, ParseError> {
    parse_udp_datagram_with_limits(input, Limits::default())
}

/// Parses one UDP AVL datagram with caller-provided wire-size limits.
///
/// The limit counts the complete datagram, including its two-byte length. Use
/// [`crate::udp::TeltonikaUdpSocket`] when you also need truncation detection and
/// source-address preservation from a socket.
///
/// # Errors
///
/// Returns the same [`ParseError`] variants as [`parse_udp_datagram`], including
/// a fatal [`crate::parser::FatalReason::DatagramTooLarge`] when the declared
/// complete wire size exceeds `limits`.
pub fn parse_udp_datagram_with_limits(
    input: &[u8],
    limits: Limits,
) -> Result<Parsed<UdpDatagram>, ParseError> {
    let result = parse_udp_datagram_inner(input, limits);
    trace_udp_result(&result);
    result
}

fn parse_udp_datagram_inner(
    input: &[u8],
    limits: Limits,
) -> Result<Parsed<UdpDatagram>, ParseError> {
    require(input.len(), 2)?;
    let (payload_length, remaining) = input.split_at(2);
    let payload_length = usize::from(u16::from_be_bytes(
        payload_length.try_into().expect("two bytes"),
    ));
    let total = payload_length.checked_add(2).ok_or(ParseError::Fatal {
        offset: 0,
        reason: FatalReason::LengthOverflow,
    })?;
    if total > limits.max_udp_wire_bytes {
        return Err(ParseError::Fatal {
            offset: 0,
            reason: FatalReason::DatagramTooLarge {
                declared: total,
                limit: limits.max_udp_wire_bytes,
            },
        });
    }
    require(remaining.len(), payload_length)?;
    let (payload, _) = remaining.split_at(payload_length);
    if total < 23 {
        return reject(total, 2, RejectionReason::InvalidPayloadLength);
    }
    let channel_packet_id = u16::from_be_bytes(payload[..2].try_into().expect("two bytes"));
    if payload[2] != 1 {
        return reject(
            total,
            4,
            RejectionReason::InvalidChannel { value: payload[2] },
        );
    }
    let avl_packet_id = payload[3];
    let imei_length = usize::from(u16::from_be_bytes(
        payload[4..6].try_into().expect("two bytes"),
    ));
    if imei_length != 15 {
        return reject(total, 6, RejectionReason::InvalidImei);
    }
    let imei_digits: [u8; 15] = payload[6..21].try_into().expect("fifteen bytes");
    let imei =
        Imei::new(imei_digits).map_err(|_| rejected(total, 8, RejectionReason::InvalidImei))?;
    let packet = parse_avl_packet(&payload[21..], total, 23)?;
    Ok(Parsed {
        value: UdpDatagram::from_parts(channel_packet_id, avl_packet_id, imei, packet),
        consumed: total,
    })
}

fn parse_avl_packet(data: &[u8], consumed: usize, base: usize) -> Result<AvlPacket, ParseError> {
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
    let mut records = Vec::with_capacity(usize::from(record_count));
    for _ in 0..record_count {
        records.push(
            parse_record(&mut cursor, codec)
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

fn parse_codec12_packet(
    data: &[u8],
    consumed: usize,
    base: usize,
) -> Result<Codec12Packet, ParseError> {
    let mut cursor = ByteCursor::new(data);
    cursor
        .skip(1)
        .map_err(|reason| rejected(consumed, base, reason))?;
    let first_count = cursor
        .u8()
        .map_err(|reason| rejected(consumed, base + 1, reason))?;
    let mut type_id = None;
    let mut payloads = Vec::with_capacity(usize::from(first_count));
    for _ in 0..first_count {
        let current_type = cursor
            .u8()
            .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
        if type_id
            .replace(current_type)
            .is_some_and(|expected| expected != current_type)
        {
            return reject(
                consumed,
                base + cursor.position() - 1,
                RejectionReason::InvalidPayloadLength,
            );
        }
        let length = cursor
            .u32()
            .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?
            as usize;
        let payload = cursor
            .take(length)
            .map_err(|reason| rejected(consumed, base + cursor.position(), reason))?;
        payloads.push(payload.to_vec());
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
    let type_id = type_id.unwrap_or(0);
    let message = match type_id {
        0x05 => Codec12Message::Command(payloads),
        0x06 => Codec12Message::Response(payloads),
        type_id => Codec12Message::Other { type_id, payloads },
    };
    Ok(Codec12Packet::from_parts(message, count_status))
}

fn parse_record(
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

fn require(actual: usize, needed: usize) -> Result<(), ParseError> {
    if actual >= needed {
        Ok(())
    } else {
        Err(ParseError::Incomplete {
            needed: NonZeroUsize::new(needed - actual).expect("positive difference"),
        })
    }
}

fn reject<T>(consumed: usize, offset: usize, reason: RejectionReason) -> Result<T, ParseError> {
    Err(rejected(consumed, offset, reason))
}

const fn rejected(consumed: usize, offset: usize, reason: RejectionReason) -> ParseError {
    ParseError::Rejected {
        consumed,
        offset,
        reason,
    }
}

#[cfg(feature = "tracing")]
fn trace_parse_result(transport: &'static str, result: &Result<Parsed<Frame>, ParseError>) {
    match result {
        Ok(parsed) => tracing::trace!(
            transport,
            outcome = "accepted",
            consumed = parsed.consumed,
            codec_id = parsed.value.codec_id(),
            "parsed protocol frame"
        ),
        Err(ParseError::Incomplete { needed }) => tracing::trace!(
            transport,
            outcome = "incomplete",
            needed = needed.get(),
            "protocol frame incomplete"
        ),
        Err(ParseError::Rejected {
            consumed, offset, ..
        }) => tracing::debug!(
            transport,
            outcome = "rejected",
            consumed,
            offset,
            "protocol frame rejected"
        ),
        Err(ParseError::Fatal { offset, .. }) => tracing::debug!(
            transport,
            outcome = "fatal",
            offset,
            "protocol framing failed"
        ),
    }
}

#[cfg(not(feature = "tracing"))]
fn trace_parse_result(_: &'static str, _: &Result<Parsed<Frame>, ParseError>) {}

#[cfg(feature = "tracing")]
fn trace_udp_result(result: &Result<Parsed<UdpDatagram>, ParseError>) {
    match result {
        Ok(parsed) => tracing::trace!(
            transport = "udp",
            outcome = "accepted",
            consumed = parsed.consumed,
            codec_id = parsed.value.packet().codec().id(),
            "parsed protocol datagram"
        ),
        Err(ParseError::Incomplete { needed }) => tracing::trace!(
            transport = "udp",
            outcome = "incomplete",
            needed = needed.get(),
            "protocol datagram incomplete"
        ),
        Err(ParseError::Rejected {
            consumed, offset, ..
        }) => tracing::debug!(
            transport = "udp",
            outcome = "rejected",
            consumed,
            offset,
            "protocol datagram rejected"
        ),
        Err(ParseError::Fatal { offset, .. }) => tracing::debug!(
            transport = "udp",
            outcome = "fatal",
            offset,
            "protocol datagram framing failed"
        ),
    }
}

#[cfg(not(feature = "tracing"))]
fn trace_udp_result(_: &Result<Parsed<UdpDatagram>, ParseError>) {}
