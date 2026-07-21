use std::{
    error::Error,
    fmt,
    num::NonZeroUsize,
    str::Utf8Error,
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    pub value: T,
    pub consumed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    UnsupportedCodec { codec_id: u8 },
    InvalidPriority { value: u8 },
    InvalidGenerationType { value: u8 },
    RecordCountMismatch { first: u8, second: u8 },
    IoCountMismatch { declared: u16, decoded: u16 },
    CrcMismatch { expected: u16, received: u32 },
    InvalidChannel { value: u8 },
    InvalidImei,
    InvalidPayloadLength,
    TrailingData,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
pub enum FatalReason {
    InvalidPreamble,
    LengthOverflow,
    FrameTooLarge { declared: usize, limit: usize },
    DatagramTooLarge { declared: usize, limit: usize },
}

impl fmt::Display for FatalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPreamble => f.write_str("invalid TCP preamble"),
            Self::LengthOverflow => f.write_str("wire length overflow"),
            Self::FrameTooLarge { declared, limit } => {
                write!(f, "frame length {declared} exceeds limit {limit}")
            }
            Self::DatagramTooLarge { declared, limit } => {
                write!(f, "datagram length {declared} exceeds limit {limit}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    Incomplete {
        needed: NonZeroUsize,
    },
    Rejected {
        consumed: usize,
        offset: usize,
        reason: RejectionReason,
    },
    Fatal {
        offset: usize,
        reason: FatalReason,
    },
}

impl fmt::Display for ParseError {
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

impl Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Limits {
    pub(crate) max_avl_wire_bytes: usize,
    pub(crate) max_codec12_wire_bytes: usize,
    pub(crate) max_udp_wire_bytes: usize,
}

impl Limits {
    pub const DEFAULT_AVL_WIRE_BYTES: usize = 1280;
    pub const DEFAULT_CODEC12_WIRE_BYTES: usize = 64 * 1024;
    pub const DEFAULT_UDP_WIRE_BYTES: usize = 2 * 1024;

    pub fn new(
        max_avl_wire_bytes: usize,
        max_codec12_wire_bytes: usize,
        max_udp_wire_bytes: usize,
    ) -> Result<Self, LimitsError> {
        let limits = Self {
            max_avl_wire_bytes,
            max_codec12_wire_bytes,
            max_udp_wire_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub const fn max_avl_wire_bytes(self) -> usize {
        self.max_avl_wire_bytes
    }

    pub const fn max_codec12_wire_bytes(self) -> usize {
        self.max_codec12_wire_bytes
    }

    pub const fn max_udp_wire_bytes(self) -> usize {
        self.max_udp_wire_bytes
    }

    pub(crate) fn validate(self) -> Result<(), LimitsError> {
        if self.max_avl_wire_bytes < 15 {
            return Err(LimitsError::AvlTooSmall);
        }
        if self.max_codec12_wire_bytes < 16 {
            return Err(LimitsError::Codec12TooSmall);
        }
        if self.max_udp_wire_bytes < 23 {
            return Err(LimitsError::UdpTooSmall);
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_avl_wire_bytes: Self::DEFAULT_AVL_WIRE_BYTES,
            max_codec12_wire_bytes: Self::DEFAULT_CODEC12_WIRE_BYTES,
            max_udp_wire_bytes: Self::DEFAULT_UDP_WIRE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsError {
    AvlTooSmall,
    Codec12TooSmall,
    UdpTooSmall,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AvlTooSmall => "AVL limit cannot contain a minimum frame",
            Self::Codec12TooSmall => "Codec 12 limit cannot contain a minimum frame",
            Self::UdpTooSmall => "UDP limit cannot contain a minimum datagram",
        })
    }
}

impl Error for LimitsError {}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Limits {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireLimits {
            max_avl_wire_bytes: usize,
            max_codec12_wire_bytes: usize,
            max_udp_wire_bytes: usize,
        }

        let value = WireLimits::deserialize(deserializer)?;
        Self::new(
            value.max_avl_wire_bytes,
            value.max_codec12_wire_bytes,
            value.max_udp_wire_bytes,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Imei([u8; 15]);

impl Imei {
    pub fn new(digits: [u8; 15]) -> Result<Self, ImeiError> {
        if digits.iter().all(u8::is_ascii_digit) {
            Ok(Self(digits))
        } else {
            Err(ImeiError)
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 15] {
        &self.0
    }

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
        let digits: [u8; 15] = value.as_bytes().try_into().map_err(|_| ImeiError)?;
        Self::new(digits)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImeiError;

impl fmt::Display for ImeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IMEI must contain exactly 15 ASCII digits")
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
pub struct AvlTimestamp(u64);

impl AvlTimestamp {
    pub const fn from_unix_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    pub const fn unix_millis(self) -> u64 {
        self.0
    }

    pub fn to_system_time(self) -> Option<SystemTime> {
        UNIX_EPOCH.checked_add(Duration::from_millis(self.0))
    }

    pub fn from_system_time(value: SystemTime) -> Result<Self, TimestampError> {
        let duration = value
            .duration_since(UNIX_EPOCH)
            .map_err(TimestampError::BeforeUnixEpoch)?;
        let milliseconds = duration
            .as_millis()
            .try_into()
            .map_err(|_| TimestampError::OutOfRange)?;
        Ok(Self(milliseconds))
    }
}

#[derive(Debug)]
pub enum TimestampError {
    BeforeUnixEpoch(SystemTimeError),
    OutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeUnixEpoch(_) => f.write_str("timestamp is before the Unix epoch"),
            Self::OutOfRange => f.write_str("timestamp milliseconds do not fit in u64"),
        }
    }
}

impl Error for TimestampError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BeforeUnixEpoch(error) => Some(error),
            Self::OutOfRange => None,
        }
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<AvlTimestamp> for chrono::DateTime<chrono::Utc> {
    type Error = &'static str;

    fn try_from(value: AvlTimestamp) -> Result<Self, Self::Error> {
        use chrono::TimeZone;
        chrono::Utc
            .timestamp_millis_opt(value.0.try_into().map_err(|_| "timestamp out of range")?)
            .single()
            .ok_or("timestamp out of range")
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<chrono::DateTime<chrono::Utc>> for AvlTimestamp {
    type Error = &'static str;

    fn try_from(value: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        let milliseconds = value
            .timestamp_millis()
            .try_into()
            .map_err(|_| "timestamp is before the Unix epoch")?;
        Ok(Self(milliseconds))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum AvlCodec {
    Codec8,
    Codec8Extended,
    Codec16,
}

impl AvlCodec {
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
pub enum Priority {
    Low,
    High,
    Panic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum GenerationType {
    OnExit,
    OnEntrance,
    OnBoth,
    Reserved,
    Hysteresis,
    OnChange,
    Eventual,
    Periodical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct IoId(u16);

impl IoId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum IoValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct IoElement {
    pub id: IoId,
    pub value: IoValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct GpsElement {
    pub longitude_raw: i32,
    pub latitude_raw: i32,
    pub altitude_meters: u16,
    pub angle_degrees: u16,
    pub satellites: u8,
    pub speed_kph: u16,
}

impl GpsElement {
    pub fn longitude_degrees(self) -> f64 {
        f64::from(self.longitude_raw) / 10_000_000.0
    }

    pub fn latitude_degrees(self) -> f64 {
        f64::from(self.latitude_raw) / 10_000_000.0
    }

    pub fn is_position_valid(self) -> bool {
        self.satellites > 0
            && self.longitude_raw.unsigned_abs() <= 1_800_000_000
            && self.latitude_raw.unsigned_abs() <= 900_000_000
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct AvlRecord {
    pub timestamp: AvlTimestamp,
    pub priority: Priority,
    pub gps: GpsElement,
    pub event_io_id: Option<IoId>,
    pub generation_type: Option<GenerationType>,
    pub io_elements: Vec<IoElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct AvlPacket {
    codec: AvlCodec,
    records: Vec<AvlRecord>,
}

impl AvlPacket {
    pub const fn codec(&self) -> AvlCodec {
        self.codec
    }

    pub fn records(&self) -> &[AvlRecord] {
        &self.records
    }

    pub(crate) fn from_parts(codec: AvlCodec, records: Vec<AvlRecord>) -> Self {
        Self { codec, records }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum CountStatus {
    Matched,
    Mismatched { first: u8, second: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum Codec12Message {
    Command(Vec<Vec<u8>>),
    Response(Vec<Vec<u8>>),
    Other { type_id: u8, payloads: Vec<Vec<u8>> },
}

impl Codec12Message {
    pub fn payloads(&self) -> &[Vec<u8>] {
        match self {
            Self::Command(payloads) | Self::Response(payloads) | Self::Other { payloads, .. } => {
                payloads
            }
        }
    }

    pub fn payload_as_str(&self, index: usize) -> Option<Result<&str, Utf8Error>> {
        self.payloads()
            .get(index)
            .map(|payload| std::str::from_utf8(payload))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Codec12Packet {
    message: Codec12Message,
    count_status: CountStatus,
}

impl Codec12Packet {
    pub const fn message(&self) -> &Codec12Message {
        &self.message
    }

    pub const fn count_status(&self) -> CountStatus {
        self.count_status
    }

    pub(crate) fn from_parts(message: Codec12Message, count_status: CountStatus) -> Self {
        Self {
            message,
            count_status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum Frame {
    Avl(AvlPacket),
    Codec12(Codec12Packet),
}

impl Frame {
    pub const fn codec_id(&self) -> u8 {
        match self {
            Self::Avl(packet) => packet.codec().id(),
            Self::Codec12(_) => 0x0c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UdpDatagram {
    channel_packet_id: u16,
    avl_packet_id: u8,
    imei: Imei,
    packet: AvlPacket,
}

impl UdpDatagram {
    pub const fn channel_packet_id(&self) -> u16 {
        self.channel_packet_id
    }
    pub const fn avl_packet_id(&self) -> u8 {
        self.avl_packet_id
    }
    pub const fn imei(&self) -> Imei {
        self.imei
    }
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
