// Message types: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols,
// section "Codec for communication over GPRS messages > Codec 12 > General
// Codec12 message structure" (accessed 2026-09-24).

/// Whether a GPRS message is a command or a response.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::GprsMessageType;
///
/// assert_eq!(GprsMessageType::try_from(0x05), Ok(GprsMessageType::Command));
/// assert_eq!(u8::from(GprsMessageType::Response), 0x06);
/// assert_eq!(GprsMessageType::try_from(0x07), Err(0x07));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
#[repr(u8)]
pub enum GprsMessageType {
    /// A command, from the server to the device (`0x05`).
    Command = 0x05,
    /// A response, from the device to the server (`0x06`).
    Response = 0x06,
}

impl TryFrom<u8> for GprsMessageType {
    /// The byte that is not a message type.
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x05 => Ok(Self::Command),
            0x06 => Ok(Self::Response),
            other => Err(other),
        }
    }
}

impl From<GprsMessageType> for u8 {
    fn from(kind: GprsMessageType) -> Self {
        kind as u8
    }
}
