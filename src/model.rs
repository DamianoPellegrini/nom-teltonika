use chrono::{DateTime, Utc};

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

#[derive(Debug, PartialEq)]
pub enum GenerationType {
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

impl From<u8> for GenerationType {
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
pub struct AVLTCPPacket {
    pub preamble: u32,
    pub data_field_len: u32,
    pub codec: Codec,
    pub records: Vec<AVLRecord>,
    pub crc16: u32,
}

#[derive(Debug, PartialEq)]
pub struct AVLRecord {
    pub datetime: DateTime<Utc>,
    pub priority: Priority,
    pub longitude: f64,
    pub latitude: f64,
    pub altitude: u16,
    pub angle: u16,
    pub satellites: u8,
    pub speed: u16,
    pub trigger_event_id: u16,
    pub generation_type: Option<GenerationType>,
    pub io_events: Vec<AVLEventIO>,
}

#[derive(Debug, PartialEq)]
pub struct AVLEventIO {
    pub id: u16,
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
