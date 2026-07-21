use std::{error::Error, fmt};

use crate::checksum::crc16;

/// Failure encoding a Codec 12 command frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// At least one command is required.
    EmptyCommandBatch,
    /// The one-byte Codec 12 quantity cannot represent the batch size.
    TooManyCommands {
        /// Commands supplied by the caller.
        actual: usize,
        /// Maximum representable command count.
        maximum: usize,
    },
    /// One command cannot fit its four-byte payload-length field.
    CommandTooLarge {
        /// Zero-based command index.
        index: usize,
        /// Command bytes supplied by the caller.
        actual: usize,
        /// Maximum representable command bytes.
        maximum: usize,
    },
    /// The complete Codec 12 data field or allocation is too large.
    FrameTooLarge,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommandBatch => f.write_str("Codec 12 command batch is empty"),
            Self::TooManyCommands { actual, maximum } => {
                write!(
                    f,
                    "Codec 12 batch contains {actual} commands, maximum is {maximum}"
                )
            }
            Self::CommandTooLarge {
                index,
                actual,
                maximum,
            } => write!(
                f,
                "Codec 12 command {index} has {actual} bytes, maximum is {maximum}"
            ),
            Self::FrameTooLarge => f.write_str("Codec 12 frame is too large"),
        }
    }
}

impl Error for EncodeError {}

/// Encodes the one-byte server decision after an IMEI handshake.
///
/// `true` produces `0x01`; `false` produces `0x00`.
pub const fn encode_imei_approval(accepted: bool) -> [u8; 1] {
    [accepted as u8]
}

/// Encodes the number of accepted TCP AVL records as a big-endian `u32`.
///
/// Acknowledgment is an application policy: pass the number of records made
/// durable or otherwise accepted, not merely the number that decoded correctly.
pub const fn encode_avl_ack(accepted_records: u32) -> [u8; 4] {
    accepted_records.to_be_bytes()
}

/// Encodes a TCP AVL negative acknowledgment as a zero record count.
pub const fn encode_avl_nack() -> [u8; 4] {
    [0; 4]
}

/// Encodes a UDP AVL acknowledgment correlated to both packet identifiers.
///
/// Copy `channel_packet_id` and `avl_packet_id` from the received datagram. A
/// shared UDP listener must not reuse identifiers from another peer.
pub const fn encode_udp_ack(
    channel_packet_id: u16,
    avl_packet_id: u8,
    accepted_records: u8,
) -> [u8; 7] {
    let id = channel_packet_id.to_be_bytes();
    [0, 5, id[0], id[1], 1, avl_packet_id, accepted_records]
}

/// Encodes one arbitrary-byte Codec 12 command in a complete TCP frame.
///
/// # Errors
///
/// Returns [`EncodeError`] when the command or complete frame is too large.
pub fn encode_codec12_command(command: &[u8]) -> Result<Vec<u8>, EncodeError> {
    encode_codec12_commands([command])
}

/// Encodes a batch of arbitrary-byte Codec 12 commands in one TCP frame.
///
/// Payloads are bytes rather than strings because Codec 12 does not guarantee
/// UTF-8. The returned frame includes preamble, lengths, duplicate count, and
/// CRC and can be written directly to an open device GPRS connection.
///
/// # Errors
///
/// Returns [`EncodeError`] for an empty batch, an unrepresentable command
/// count or size, or a complete frame that cannot be represented or allocated.
pub fn encode_codec12_commands<'a>(
    commands: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, EncodeError> {
    let commands: Vec<&[u8]> = commands.into_iter().collect();
    if commands.is_empty() {
        return Err(EncodeError::EmptyCommandBatch);
    }
    let maximum_commands = usize::from(u8::MAX);
    if commands.len() > maximum_commands {
        return Err(EncodeError::TooManyCommands {
            actual: commands.len(),
            maximum: maximum_commands,
        });
    }
    let maximum_command = u32::MAX as usize;
    let mut payload_len = 3usize;
    for (index, command) in commands.iter().enumerate() {
        if command.len() > maximum_command {
            return Err(EncodeError::CommandTooLarge {
                index,
                actual: command.len(),
                maximum: maximum_command,
            });
        }
        payload_len = payload_len
            .checked_add(5)
            .and_then(|size| size.checked_add(command.len()))
            .ok_or(EncodeError::FrameTooLarge)?;
    }
    if payload_len > u32::MAX as usize {
        return Err(EncodeError::FrameTooLarge);
    }
    let frame_len = payload_len
        .checked_add(12)
        .ok_or(EncodeError::FrameTooLarge)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(frame_len)
        .map_err(|_| EncodeError::FrameTooLarge)?;
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(&(payload_len as u32).to_be_bytes());
    output.push(0x0c);
    output.push(commands.len() as u8);
    for command in commands {
        output.push(0x05);
        output.extend_from_slice(&(command.len() as u32).to_be_bytes());
        output.extend_from_slice(command);
    }
    // Byte 9 is the leading command count. Reuse it for the required duplicate
    // count so both fields cannot diverge during encoding.
    output.push(output[9]);
    let checksum = crc16(&output[8..]);
    output.extend_from_slice(&(checksum as u32).to_be_bytes());
    Ok(output)
}
