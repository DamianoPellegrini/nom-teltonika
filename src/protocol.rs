use std::{
    error::Error,
    fmt,
    num::NonZeroUsize,
    str::Utf8Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A successfully decoded value and the number of input bytes it occupies.
///
/// The value is owned and does not borrow the input. Slice-decoder callers can
/// preserve concatenated data with `&input[decoded.consumed..]`.
pub struct Decoded<T> {
    /// The validated protocol value.
    pub value: T,
    /// Number of bytes belonging to the decoded value, measured from input byte zero.
    pub consumed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Why a complete, safely delimited frame or datagram was rejected.
///
/// A rejection does not make the following transport bytes ambiguous. Use the
/// enclosing [`DecodeError::Rejected::consumed`] value—not `offset`—to advance a
/// receive buffer.
pub enum RejectionReason {
    /// An AVL packet declares no records.
    EmptyAvlPacket,
    /// A Codec 12 frame contains no messages.
    EmptyCodec12Batch,
    /// Messages in one Codec 12 frame do not share the same type byte.
    Codec12TypeMismatch {
        /// Type byte established by the first message.
        expected: u8,
        /// Different type byte found later in the batch.
        actual: u8,
    },
    /// A Codec 12 frame contains more messages than its one-byte quantities can represent.
    TooManyCodec12Messages {
        /// Number of messages decoded from the data field.
        actual: usize,
        /// Maximum representable message count.
        maximum: usize,
    },
    /// The packet uses a codec that this crate does not decode.
    UnsupportedCodec {
        /// Codec byte found on the wire.
        codec_id: u8,
    },
    /// An AVL record contains an undefined priority byte.
    InvalidPriority {
        /// Priority byte found on the wire.
        value: u8,
    },
    /// A Codec 16 record contains an undefined generation type.
    InvalidGenerationType {
        /// Generation-type byte found on the wire.
        value: u8,
    },
    /// The two AVL record counts do not agree.
    RecordCountMismatch {
        /// Count before the records.
        first: u8,
        /// Count after the records.
        second: u8,
    },
    /// An AVL record's total IO count differs from its decoded groups.
    IoCountMismatch {
        /// Total IO count declared by the record.
        declared: u16,
        /// Sum of the decoded IO group counts.
        decoded: u16,
    },
    /// The received TCP checksum differs from CRC-16/IBM over the data field.
    CrcMismatch {
        /// Locally computed 16-bit checksum.
        expected: u16,
        /// Four-byte wire field carrying the received checksum.
        received: u32,
    },
    /// A UDP packet does not use the required `0x01` AVL channel.
    InvalidChannel {
        /// Channel byte found on the wire.
        value: u8,
    },
    /// An IMEI length or digit is invalid.
    InvalidImei,
    /// Length fields cannot delimit the codec-specific payload safely.
    InvalidPayloadLength,
    /// Bytes remain inside an otherwise decoded, length-delimited payload.
    TrailingData,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAvlPacket => f.write_str("AVL packet contains no records"),
            Self::EmptyCodec12Batch => f.write_str("Codec 12 batch contains no messages"),
            Self::Codec12TypeMismatch { expected, actual } => write!(
                f,
                "Codec 12 message type mismatch (expected {expected:#04x}, found {actual:#04x})"
            ),
            Self::TooManyCodec12Messages { actual, maximum } => write!(
                f,
                "Codec 12 batch contains {actual} messages, maximum is {maximum}"
            ),
            Self::UnsupportedCodec { codec_id } => write!(f, "unsupported codec 0x{codec_id:02x}"),
            Self::InvalidPriority { value } => write!(f, "invalid priority {value}"),
            Self::InvalidGenerationType { value } => {
                write!(f, "invalid generation type {value}")
            }
            Self::RecordCountMismatch { first, second } => {
                write!(f, "record count mismatch ({first} != {second})")
            }
            Self::IoCountMismatch { declared, decoded } => {
                write!(f, "IO count mismatch ({declared} != {decoded})")
            }
            Self::CrcMismatch { expected, received } => {
                write!(
                    f,
                    "CRC mismatch (expected {expected:#06x}, received {received:#010x})"
                )
            }
            Self::InvalidChannel { value } => write!(f, "invalid UDP channel byte {value:#04x}"),
            Self::InvalidImei => f.write_str("invalid IMEI"),
            Self::InvalidPayloadLength => f.write_str("invalid payload length"),
            Self::TrailingData => f.write_str("unexpected bytes inside the delimited payload"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Why framing is unsafe to resume from automatically.
///
/// The decoder provides a diagnostic byte offset but no consumable length. Close
/// or reset the transport unless your application has an externally justified
/// resynchronization strategy.
pub enum FatalReason {
    /// A TCP frame does not start with four zero bytes.
    InvalidPreamble,
    /// An IMEI handshake declares a length other than the required 15 bytes.
    InvalidImeiLength {
        /// Length declared by the handshake prefix.
        declared: usize,
        /// Required IMEI byte length.
        expected: usize,
    },
    /// Declared lengths overflow the platform's addressable size.
    LengthOverflow,
    /// A TCP frame's declared complete wire size exceeds its configured limit.
    FrameTooLarge {
        /// Complete wire bytes declared by the header.
        declared: usize,
        /// Configured maximum complete wire bytes for the detected codec family.
        limit: usize,
    },
}

impl fmt::Display for FatalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPreamble => f.write_str("invalid TCP preamble"),
            Self::InvalidImeiLength { declared, expected } => write!(
                f,
                "IMEI handshake declares {declared} bytes, expected {expected}"
            ),
            Self::LengthOverflow => f.write_str("wire length overflow"),
            Self::FrameTooLarge { declared, limit } => {
                write!(f, "frame length {declared} exceeds limit {limit}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// A decoder failure with an explicit buffering and recovery contract.
///
/// The three variants distinguish waiting for bytes from discarding one known
/// bad packet and abandoning untrusted framing. This distinction is what makes
/// the slice decoders suitable for incremental network buffers.
pub enum DecodeError {
    /// The prefix is valid but does not yet contain the declared packet.
    Incomplete {
        /// Exact minimum number of additional bytes needed at this stage.
        needed: NonZeroUsize,
    },
    /// A complete packet was delimited safely but failed validation.
    Rejected {
        /// Number of bytes that may be removed from the receive buffer.
        consumed: usize,
        /// Diagnostic byte offset, relative to the decoder input.
        offset: usize,
        /// Validation failure that caused the rejection.
        reason: RejectionReason,
    },
    /// Framing is untrusted and the decoder cannot identify a safe next packet.
    Fatal {
        /// Diagnostic byte offset, relative to the decoder input.
        offset: usize,
        /// Framing failure that prevents safe recovery.
        reason: FatalReason,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => {
                write!(f, "incomplete input: {} more byte(s) needed", needed)
            }
            Self::Rejected { offset, reason, .. } => {
                write!(f, "frame rejected at byte {offset}: {reason}")
            }
            Self::Fatal { offset, reason } => {
                write!(f, "fatal framing error at byte {offset}: {reason}")
            }
        }
    }
}

impl Error for DecodeError {}

/// Failure decoding one complete UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecodeError {
    /// Fewer than the two bytes required for the UDP length prefix were received.
    TruncatedHeader {
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// The declared complete datagram size differs from the supplied slice.
    LengthMismatch {
        /// Complete bytes declared by the prefix.
        declared: usize,
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// The declared complete datagram exceeds the configured safety limit.
    DatagramTooLarge {
        /// Complete bytes declared by the prefix.
        declared: usize,
        /// Configured maximum complete datagram size.
        limit: usize,
    },
    /// The datagram is delimited but its channel or AVL payload is invalid.
    Invalid {
        /// Diagnostic byte offset relative to the datagram start.
        offset: usize,
        /// Validation failure at that offset.
        reason: RejectionReason,
    },
}

impl fmt::Display for UdpDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => {
                write!(f, "UDP header is truncated: received {actual} byte(s)")
            }
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "UDP datagram declares {declared} bytes but slice contains {actual}"
            ),
            Self::DatagramTooLarge { declared, limit } => {
                write!(f, "UDP datagram length {declared} exceeds limit {limit}")
            }
            Self::Invalid { offset, reason } => {
                write!(f, "UDP datagram invalid at byte {offset}: {reason}")
            }
        }
    }
}

impl Error for UdpDecodeError {}

/// Validated upper bounds for complete TCP frames accepted from untrusted peers.
///
/// The 1280-byte AVL default comes from Teltonika's *Data Sending Protocols*,
/// AVL data packet section (accessed 2026-07-21). Some models document 512
/// bytes and can opt into that value explicitly. The Codec 12 default is a
/// local safety policy, not a Teltonika protocol limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct TcpLimits {
    max_avl_frame_bytes: usize,
    max_codec12_frame_bytes: usize,
}

impl TcpLimits {
    /// Teltonika's documented maximum AVL packet size, including TCP framing.
    pub const DEFAULT_MAX_AVL_FRAME_BYTES: usize = 1280;
    /// Local safety policy for Codec 12 frames; this is not a Teltonika wire limit.
    pub const DEFAULT_MAX_CODEC12_FRAME_BYTES: usize = 64 * 1024;
    /// Smallest supported complete AVL TCP frame.
    pub const MIN_AVL_FRAME_BYTES: usize = 45;
    /// Smallest supported complete Codec 12 TCP frame.
    pub const MIN_CODEC12_FRAME_BYTES: usize = 20;

    /// Creates validated TCP frame limits.
    pub fn new(
        max_avl_frame_bytes: usize,
        max_codec12_frame_bytes: usize,
    ) -> Result<Self, LimitsError> {
        if max_avl_frame_bytes < Self::MIN_AVL_FRAME_BYTES {
            return Err(LimitsError::AvlFrameTooSmall {
                actual: max_avl_frame_bytes,
                minimum: Self::MIN_AVL_FRAME_BYTES,
            });
        }
        if max_codec12_frame_bytes < Self::MIN_CODEC12_FRAME_BYTES {
            return Err(LimitsError::Codec12FrameTooSmall {
                actual: max_codec12_frame_bytes,
                minimum: Self::MIN_CODEC12_FRAME_BYTES,
            });
        }
        Ok(Self {
            max_avl_frame_bytes,
            max_codec12_frame_bytes,
        })
    }

    /// Returns the maximum complete AVL TCP frame size.
    pub const fn max_avl_frame_bytes(self) -> usize {
        self.max_avl_frame_bytes
    }

    /// Returns the maximum complete Codec 12 TCP frame size.
    pub const fn max_codec12_frame_bytes(self) -> usize {
        self.max_codec12_frame_bytes
    }
}

impl Default for TcpLimits {
    fn default() -> Self {
        Self {
            max_avl_frame_bytes: Self::DEFAULT_MAX_AVL_FRAME_BYTES,
            max_codec12_frame_bytes: Self::DEFAULT_MAX_CODEC12_FRAME_BYTES,
        }
    }
}

/// Validated upper bound for complete UDP datagrams.
///
/// Framing and the `u16` payload-size field follow Teltonika's *Codec*, UDP
/// channel protocol section (accessed 2026-07-21). The 2048-byte default is a
/// local safety policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UdpLimits {
    max_datagram_bytes: usize,
}

impl UdpLimits {
    /// Local safety policy for UDP datagrams; this is not a Teltonika device limit.
    pub const DEFAULT_MAX_DATAGRAM_BYTES: usize = 2 * 1024;
    /// Smallest supported complete UDP AVL datagram.
    pub const MIN_DATAGRAM_BYTES: usize = 56;
    /// Largest complete datagram representable by the two-byte payload length prefix.
    pub const MAX_DATAGRAM_BYTES: usize = u16::MAX as usize + 2;

    /// Creates a validated UDP datagram limit.
    pub fn new(max_datagram_bytes: usize) -> Result<Self, LimitsError> {
        if max_datagram_bytes < Self::MIN_DATAGRAM_BYTES {
            return Err(LimitsError::UdpDatagramTooSmall {
                actual: max_datagram_bytes,
                minimum: Self::MIN_DATAGRAM_BYTES,
            });
        }
        if max_datagram_bytes > Self::MAX_DATAGRAM_BYTES {
            return Err(LimitsError::UdpDatagramTooLarge {
                actual: max_datagram_bytes,
                maximum: Self::MAX_DATAGRAM_BYTES,
            });
        }
        Ok(Self { max_datagram_bytes })
    }

    /// Returns the maximum complete UDP datagram size.
    pub const fn max_datagram_bytes(self) -> usize {
        self.max_datagram_bytes
    }
}

impl Default for UdpLimits {
    fn default() -> Self {
        Self {
            max_datagram_bytes: Self::DEFAULT_MAX_DATAGRAM_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// An invalid TCP or UDP limit configuration.
pub enum LimitsError {
    /// The AVL TCP frame limit is below the operational minimum.
    AvlFrameTooSmall {
        /// Configured limit.
        actual: usize,
        /// Operational minimum.
        minimum: usize,
    },
    /// The Codec 12 TCP frame limit is below the operational minimum.
    Codec12FrameTooSmall {
        /// Configured limit.
        actual: usize,
        /// Operational minimum.
        minimum: usize,
    },
    /// The UDP datagram limit is below the operational minimum.
    UdpDatagramTooSmall {
        /// Configured limit.
        actual: usize,
        /// Operational minimum.
        minimum: usize,
    },
    /// The UDP datagram limit cannot be represented by the wire prefix.
    UdpDatagramTooLarge {
        /// Configured limit.
        actual: usize,
        /// Largest wire-representable complete datagram.
        maximum: usize,
    },
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AvlFrameTooSmall { actual, minimum } => {
                write!(f, "AVL frame limit {actual} is below minimum {minimum}")
            }
            Self::Codec12FrameTooSmall { actual, minimum } => write!(
                f,
                "Codec 12 frame limit {actual} is below minimum {minimum}"
            ),
            Self::UdpDatagramTooSmall { actual, minimum } => {
                write!(f, "UDP datagram limit {actual} is below minimum {minimum}")
            }
            Self::UdpDatagramTooLarge { actual, maximum } => write!(
                f,
                "UDP datagram limit {actual} exceeds wire maximum {maximum}"
            ),
        }
    }
}

impl Error for LimitsError {}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for TcpLimits {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireLimits {
            max_avl_frame_bytes: usize,
            max_codec12_frame_bytes: usize,
        }

        let value = WireLimits::deserialize(deserializer)?;
        Self::new(value.max_avl_frame_bytes, value.max_codec12_frame_bytes)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for UdpLimits {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireLimits {
            max_datagram_bytes: usize,
        }
        let value = WireLimits::deserialize(deserializer)?;
        Self::new(value.max_datagram_bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// A validated 15-digit International Mobile Equipment Identity.
///
/// The fixed-size representation prevents a decoded or deserialized `Imei` from
/// carrying the wrong length or non-decimal bytes. Its [`Display`](fmt::Display)
/// implementation reveals the identifier, so avoid logging it unintentionally.
pub struct Imei([u8; 15]);

impl Imei {
    /// Creates an IMEI from exactly 15 ASCII digits.
    ///
    /// # Errors
    ///
    /// Returns [`ImeiError`] if any byte is not in `0..=9`.
    pub fn new(digits: [u8; 15]) -> Result<Self, ImeiError> {
        match digits.iter().position(|digit| !digit.is_ascii_digit()) {
            Some(index) => Err(ImeiError::InvalidDigit { index }),
            None => Ok(Self(digits)),
        }
    }

    /// Returns the validated ASCII digits.
    pub const fn as_bytes(&self) -> &[u8; 15] {
        &self.0
    }

    /// Returns the validated digits as a string slice.
    ///
    /// This conversion cannot fail because construction validates ASCII.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("validated ASCII IMEI")
    }
}

impl fmt::Display for Imei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Imei {
    type Error = ImeiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let digits: [u8; 15] =
            value
                .as_bytes()
                .try_into()
                .map_err(|_| ImeiError::InvalidLength {
                    actual: value.len(),
                })?;
        Self::new(digits)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Error returned when an IMEI is not exactly 15 ASCII digits.
pub enum ImeiError {
    /// The value does not contain exactly 15 bytes.
    InvalidLength {
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// A byte at the given zero-based index is not an ASCII digit.
    InvalidDigit {
        /// Zero-based index of the invalid byte.
        index: usize,
    },
}

impl fmt::Display for ImeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual } => write!(f, "IMEI length is {actual}, expected 15"),
            Self::InvalidDigit { index } => write!(f, "IMEI contains a non-digit at index {index}"),
        }
    }
}

impl Error for ImeiError {}

#[cfg(feature = "serde")]
impl Serialize for Imei {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Imei {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Imei::try_from(value.as_str()).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// An AVL timestamp stored as unsigned milliseconds since the Unix epoch.
///
/// Keeping the exact wire integer avoids choosing a date-time dependency in the
/// core model. Use [`AvlTimestamp::to_system_time`] or enable `chrono` for a
/// checked ecosystem conversion.
pub struct AvlTimestamp(u64);

impl AvlTimestamp {
    /// Creates a timestamp from the exact unsigned wire value.
    pub const fn from_unix_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Returns milliseconds since the Unix epoch.
    pub const fn unix_millis(self) -> u64 {
        self.0
    }

    /// Converts to [`SystemTime`].
    pub fn to_system_time(self) -> Result<SystemTime, TimestampError> {
        UNIX_EPOCH
            .checked_add(Duration::from_millis(self.0))
            .ok_or(TimestampError::OutOfRange)
    }

    /// Converts a [`SystemTime`] without truncating a negative timestamp.
    ///
    /// Sub-millisecond precision is truncated because the AVL wire format stores
    /// milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::BeforeUnixEpoch`] for negative instants and
    /// [`TimestampError::OutOfRange`] when milliseconds do not fit in `u64`.
    pub fn from_system_time(value: SystemTime) -> Result<Self, TimestampError> {
        let duration = value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TimestampError::BeforeUnixEpoch)?;
        let milliseconds = duration
            .as_millis()
            .try_into()
            .map_err(|_| TimestampError::OutOfRange)?;
        Ok(Self(milliseconds))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failure converting a time value into [`AvlTimestamp`].
pub enum TimestampError {
    /// The input precedes the Unix epoch and cannot be represented by the wire type.
    BeforeUnixEpoch,
    /// The elapsed millisecond count does not fit in the wire type.
    OutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeUnixEpoch => f.write_str("timestamp is before the Unix epoch"),
            Self::OutOfRange => f.write_str("timestamp milliseconds do not fit in u64"),
        }
    }
}

impl Error for TimestampError {}

#[cfg(feature = "chrono")]
impl TryFrom<AvlTimestamp> for chrono::DateTime<chrono::Utc> {
    type Error = TimestampError;

    fn try_from(value: AvlTimestamp) -> Result<Self, Self::Error> {
        use chrono::TimeZone;
        chrono::Utc
            .timestamp_millis_opt(value.0.try_into().map_err(|_| TimestampError::OutOfRange)?)
            .single()
            .ok_or(TimestampError::OutOfRange)
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<chrono::DateTime<chrono::Utc>> for AvlTimestamp {
    type Error = TimestampError;

    fn try_from(value: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        let milliseconds = value
            .timestamp_millis()
            .try_into()
            .map_err(|_| TimestampError::BeforeUnixEpoch)?;
        Ok(Self(milliseconds))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A supported AVL data codec.
pub enum AvlCodec {
    /// Codec 8 (`0x08`).
    Codec8,
    /// Codec 8 Extended (`0x8e`).
    Codec8Extended,
    /// Codec 16 (`0x10`).
    Codec16,
}

impl AvlCodec {
    /// Returns the codec byte used on the wire.
    pub const fn id(self) -> u8 {
        match self {
            Self::Codec8 => 0x08,
            Self::Codec8Extended => 0x8e,
            Self::Codec16 => 0x10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// Priority recorded for an AVL event.
pub enum Priority {
    /// Low-priority record (`0`).
    Low,
    /// High-priority record (`1`).
    High,
    /// Panic-priority record (`2`).
    Panic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// Codec 16 event-generation condition.
pub enum GenerationType {
    /// Generate when leaving the configured range.
    OnExit,
    /// Generate when entering the configured range.
    OnEntrance,
    /// Generate on both entrance and exit.
    OnBoth,
    /// Reserved wire value; its device behavior is model-specific.
    Reserved,
    /// Generate according to the configured hysteresis.
    Hysteresis,
    /// Generate when the IO value changes.
    OnChange,
    /// Eventual generation condition as defined by the device configuration.
    Eventual,
    /// Generate periodically.
    Periodical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A numeric Teltonika IO element identifier.
///
/// The identifier's meaning, size, multiplier, and units depend on device model
/// and firmware. Resolve it against that device's *Data Sending Parameters ID*
/// documentation instead of applying one global mapping.
pub struct IoId(u16);

impl IoId {
    /// Creates an IO identifier from its numeric wire value.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric wire value.
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A decoded IO value, preserving its wire width or byte payload.
pub enum IoValue {
    /// One-byte unsigned value.
    U8(u8),
    /// Two-byte big-endian unsigned value.
    U16(u16),
    /// Four-byte big-endian unsigned value.
    U32(u32),
    /// Eight-byte big-endian unsigned value.
    U64(u64),
    /// Codec 8 Extended variable-length bytes.
    ///
    /// The payload is not assumed to be text and is serialized as bytes when
    /// the `serde` feature is enabled.
    Bytes(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// One IO measurement decoded from an AVL record.
///
/// A measurement is not necessarily the event that triggered the record. Check
/// [`AvlRecord::event_io_id`] separately for the triggering identifier.
pub struct IoElement {
    /// Device- and firmware-specific IO identifier.
    pub id: IoId,
    /// Exact decoded value and wire width.
    pub value: IoValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// GPS data embedded in one AVL record.
///
/// Coordinates retain the exact signed wire integers, scaled by 10,000,000.
/// The decoder intentionally preserves anomalous coordinates; call
/// [`GpsElement::is_position_valid`] before treating them as a fix.
pub struct GpsElement {
    /// Signed longitude scaled by 10,000,000.
    pub longitude_raw: i32,
    /// Signed latitude scaled by 10,000,000.
    pub latitude_raw: i32,
    /// Altitude above sea level in meters.
    pub altitude_meters: u16,
    /// Heading in degrees.
    pub angle_degrees: u16,
    /// Number of visible satellites; zero marks an invalid position.
    pub satellites: u8,
    /// Ground speed in kilometres per hour.
    pub speed_kph: u16,
}

impl GpsElement {
    /// Returns longitude in degrees as a display-oriented floating-point value.
    ///
    /// Use [`GpsElement::longitude_raw`] when exact wire equality matters.
    pub fn longitude_degrees(self) -> f64 {
        f64::from(self.longitude_raw) / 10_000_000.0
    }

    /// Returns latitude in degrees as a display-oriented floating-point value.
    ///
    /// Use [`GpsElement::latitude_raw`] when exact wire equality matters.
    pub fn latitude_degrees(self) -> f64 {
        f64::from(self.latitude_raw) / 10_000_000.0
    }

    /// Reports whether satellite count and coordinate ranges describe a valid fix.
    ///
    /// This structural check does not validate device calibration, accuracy, or
    /// whether `(0, 0)` is meaningful to your application.
    pub fn is_position_valid(self) -> bool {
        self.satellites > 0
            && self.longitude_raw.unsigned_abs() <= 1_800_000_000
            && self.latitude_raw.unsigned_abs() <= 900_000_000
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// One timestamped AVL record with GPS and IO measurements.
pub struct AvlRecord {
    /// Device timestamp in unsigned Unix milliseconds.
    pub timestamp: AvlTimestamp,
    /// Device-assigned event priority.
    pub priority: Priority,
    /// Exact decoded GPS data.
    pub gps: GpsElement,
    /// IO identifier that triggered the record, or `None` for wire value zero.
    pub event_io_id: Option<IoId>,
    /// Codec 16 generation condition; `None` for Codec 8 families.
    pub generation_type: Option<GenerationType>,
    /// All IO measurements carried by this record, in wire-group order.
    pub io_elements: Vec<IoElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A validated owned packet of AVL records.
///
/// Construction is private because codec widths, record counts, and IO counts
/// must agree. Obtain packets from the TCP or UDP decoders.
pub struct AvlPacket {
    codec: AvlCodec,
    records: Vec<AvlRecord>,
}

impl AvlPacket {
    /// Returns the AVL codec that determines field widths in this packet.
    pub const fn codec(&self) -> AvlCodec {
        self.codec
    }

    /// Returns validated records in their original wire order.
    pub fn records(&self) -> &[AvlRecord] {
        &self.records
    }

    pub(crate) fn from_parts(codec: AvlCodec, records: Vec<AvlRecord>) -> Self {
        Self { codec, records }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// Agreement between the two Codec 12 command or response counts.
///
/// Codec 12 keeps a mismatch as observable metadata because the declared frame
/// length can still delimit every payload safely. AVL count mismatches instead
/// reject the packet.
pub enum CountStatus {
    /// Both count bytes agree.
    Matched,
    /// The leading and trailing count bytes differ.
    Mismatched {
        /// Count before the payloads.
        first: u8,
        /// Count after the payloads.
        second: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// Codec 12 payloads classified by their type byte.
///
/// Payloads remain arbitrary bytes: ASCII commands are conventional, not a
/// wire invariant. Unknown type IDs are preserved for device-specific handling.
pub enum Codec12Message {
    /// Server-to-device command payloads (`0x05`).
    Command(Vec<Vec<u8>>),
    /// Device-to-server response payloads (`0x06`).
    Response(Vec<Vec<u8>>),
    /// Payloads with a device-specific type byte.
    Other {
        /// Unrecognized type byte shared by every payload in the packet.
        type_id: u8,
        /// Payload bytes in wire order.
        payloads: Vec<Vec<u8>>,
    },
}

impl Codec12Message {
    /// Returns all payloads in wire order, independent of message type.
    pub fn payloads(&self) -> &[Vec<u8>] {
        match self {
            Self::Command(payloads) | Self::Response(payloads) | Self::Other { payloads, .. } => {
                payloads
            }
        }
    }

    /// Attempts to view one payload as UTF-8 without changing its byte storage.
    ///
    /// Returns `Ok(None)` when `index` is out of bounds and an error only when
    /// the selected payload is not valid UTF-8.
    pub fn payload_as_str(&self, index: usize) -> Result<Option<&str>, Utf8Error> {
        self.payloads()
            .get(index)
            .map(|payload| std::str::from_utf8(payload))
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A validated owned Codec 12 packet.
pub struct Codec12Packet {
    message: Codec12Message,
    count_status: CountStatus,
    counts_match: bool,
}

impl Codec12Packet {
    /// Returns the classified command, response, or device-specific message.
    pub const fn message(&self) -> &Codec12Message {
        &self.message
    }

    /// Returns whether the leading and trailing payload counts agree.
    pub const fn count_status(&self) -> CountStatus {
        self.count_status
    }

    /// Returns whether both wire quantities equal the decoded message count.
    pub const fn counts_match(&self) -> bool {
        self.counts_match
    }

    pub(crate) fn from_parts(
        message: Codec12Message,
        count_status: CountStatus,
        counts_match: bool,
    ) -> Self {
        Self {
            message,
            count_status,
            counts_match,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A supported owned Teltonika TCP frame.
///
/// This enum is non-exhaustive so future codecs can be added without implying
/// that unsupported wire formats are already accepted.
pub enum Frame {
    /// Codec 8, Codec 8 Extended, or Codec 16 AVL data.
    Avl(AvlPacket),
    /// Codec 12 commands, responses, or device-specific messages.
    Codec12(Codec12Packet),
}

impl Frame {
    /// Returns the codec ID found on the wire.
    pub const fn codec_id(&self) -> u8 {
        match self {
            Self::Avl(packet) => packet.codec().id(),
            Self::Codec12(_) => 0x0c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
/// A validated UDP channel envelope containing one owned AVL packet.
pub struct UdpDatagram {
    channel_packet_id: u16,
    avl_packet_id: u8,
    imei: Imei,
    packet: AvlPacket,
}

impl UdpDatagram {
    /// Returns the two-byte packet ID used to correlate the UDP channel ACK.
    pub const fn channel_packet_id(&self) -> u16 {
        self.channel_packet_id
    }
    /// Returns the one-byte AVL packet ID echoed in the UDP ACK.
    pub const fn avl_packet_id(&self) -> u8 {
        self.avl_packet_id
    }
    /// Returns the validated sending-device IMEI.
    pub const fn imei(&self) -> Imei {
        self.imei
    }
    /// Returns the enclosed validated AVL packet.
    pub const fn packet(&self) -> &AvlPacket {
        &self.packet
    }

    pub(crate) fn from_parts(
        channel_packet_id: u16,
        avl_packet_id: u8,
        imei: Imei,
        packet: AvlPacket,
    ) -> Self {
        Self {
            channel_packet_id,
            avl_packet_id,
            imei,
            packet,
        }
    }
}
