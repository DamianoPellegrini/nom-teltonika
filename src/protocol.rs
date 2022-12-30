use chrono::{DateTime, Utc};
use nom::Finish;

use crate::parser::{udp_datagram, tcp_packet};

/// Represent the device Codec
/// 
/// | TCP/UDP | GPRS |
/// |---------|------|
/// | C8      | C12  |
/// | C8Ext   | C13  |
/// | C16     | C14  |
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Codec {
    C8,
    C8Ext,
    C16,
    C12,
    C13,
    C14,
}

impl From<u8> for Codec {
    fn from(value: u8) -> Self {
        match value {
            0x08 => Self::C8,
            0x8E => Self::C8Ext,
            0x10 => Self::C16,
            0x0C => Self::C12,
            0x0D => Self::C13,
            0x0E => Self::C14,
            _ => panic!("Unknown value: {}", value),
        }
    }
}

impl Into<u8> for Codec {
    fn into(self) -> u8 {
        match self {
            Self::C8 => 0x08,
            Self::C8Ext => 0x8E,
            Self::C16 => 0x10,
            Self::C12 => 0x0C,
            Self::C13 => 0x0D,
            Self::C14 => 0x0E,
        }
    }
}

/// Record priority
/// 
/// Indicates based on configuration how important the record is
#[derive(Debug, PartialEq)]
pub enum Priority {
    Low,
    High,
    Panic,
}

impl From<u8> for Priority {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Low,
            0x01 => Self::High,
            0x02 => Self::Panic,
            _ => panic!("Unknown value: {}", value),
        }
    }
}

/// Event generation
/// 
/// Indicates the cause for the event trigger see [`AVLRecord`]
#[derive(Debug, PartialEq)]
pub enum EventGenerationCause {
    None,
    OnExit,
    OnEntrance,
    OnBoth,
    Reserved,
    Hysteresis,
    OnChange,
    Eventual,
    Periodical,
}

impl From<u8> for EventGenerationCause {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::OnExit,
            1 => Self::OnEntrance,
            2 => Self::OnBoth,
            3 => Self::Reserved,
            4 => Self::Hysteresis,
            5 => Self::OnChange,
            6 => Self::Eventual,
            7 => Self::Periodical,
            _ => panic!("Unknown value: {}", value),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AVLDatagram {
    pub packet_id: u16,
    pub avl_packet_id: u8,
    pub imei: String,
    pub codec: Codec,
    /// All the records sent with this packet
    pub records: Vec<AVLRecord>,
}

impl<'a> TryFrom<&'a [u8]> for AVLDatagram {
    type Error = nom::error::Error<&'a[u8]>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        match udp_datagram(value).finish() {
            Ok((_, datagram)) => Ok(datagram),
            Err(e) => Err(e),
        }
    }
}

/// Packet sent by the device
/// 
/// Based on [Teltonika Protocol Wiki](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols#)
#[derive(Debug, PartialEq)]
pub struct AVLPacket {
    pub codec: Codec,
    /// All the records sent with this packet
    pub records: Vec<AVLRecord>,
    /// CRC16 Calculated using [IBM/CRC16][super::crc16] algorithm and 0xA001 polynomial
    pub crc16: u32,
}

impl<'a> TryFrom<&'a [u8]> for AVLPacket {
    type Error = nom::error::Error<&'a[u8]>;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        match tcp_packet(value).finish() {
            Ok((_, packet)) => Ok(packet),
            Err(e) => Err(e),
        }
    }
}

/// Location and IO Status inforamtion at a certain point in time
#[derive(Debug, PartialEq)]
pub struct AVLRecord {
    /// In Utc Dates
    pub datetime: DateTime<Utc>,
    /// How
    pub priority: Priority,
    pub longitude: f64,
    pub latitude: f64,
    pub altitude: u16,
    /// Degrees
    pub angle: u16,
    /// How many satellites were connected
    pub satellites: u8,
    /// Km/h
    pub speed: u16,
    /// Which event triggered the recording
    pub trigger_event_id: u16,
    /// How was the event generated see [`EventGenerationCause`]
    pub generation_type: Option<EventGenerationCause>,
    /// Current IO Event statuses
    pub io_events: Vec<AVLEventIO>,
}

/// IO event status
#[derive(Debug, PartialEq)]
pub struct AVLEventIO {
    /// Event ID
    pub id: u16,
    /// Raw event value.
    /// 
    /// Should be mapped to the real values using a AVL IO ID List
    pub value: AVLEventIOValue,
}

#[derive(Debug, PartialEq)]
pub enum AVLEventIOValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Variable(Vec<u8>),
}
