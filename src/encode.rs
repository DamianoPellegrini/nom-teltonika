use std::io::{self, Write};

use crate::crc16;

/// Encodes the one-byte server decision after an IMEI handshake.
pub const fn encode_imei_approval(accepted: bool) -> [u8; 1] {
    [accepted as u8]
}

/// Encodes the number of accepted TCP AVL records.
pub const fn encode_avl_ack(accepted_records: u32) -> [u8; 4] {
    accepted_records.to_be_bytes()
}

/// Encodes a TCP AVL negative acknowledgment.
pub const fn encode_avl_nack() -> [u8; 4] {
    [0; 4]
}

/// Encodes a UDP AVL acknowledgment correlated to both packet identifiers.
pub const fn encode_udp_ack(
    channel_packet_id: u16,
    avl_packet_id: u8,
    accepted_records: u8,
) -> [u8; 7] {
    let id = channel_packet_id.to_be_bytes();
    [0, 5, id[0], id[1], 1, avl_packet_id, accepted_records]
}

/// Encodes one Codec 12 command.
pub fn encode_codec12_command(command: &[u8]) -> Vec<u8> {
    encode_codec12_commands([command])
}

/// Encodes a batch of Codec 12 commands.
pub fn encode_codec12_commands<'a>(commands: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let commands: Vec<&[u8]> = commands.into_iter().collect();
    let payload_len = commands
        .iter()
        .try_fold(0usize, |size, command| size.checked_add(5 + command.len()))
        .and_then(|size| size.checked_add(3))
        .expect("Codec 12 command batch is too large");
    assert!(
        commands.len() <= u8::MAX as usize,
        "too many Codec 12 commands"
    );
    assert!(
        payload_len <= u32::MAX as usize,
        "Codec 12 command batch is too large"
    );

    let mut output = Vec::with_capacity(payload_len + 12);
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(&(payload_len as u32).to_be_bytes());
    output.push(0x0c);
    output.push(commands.len() as u8);
    for command in commands {
        output.push(0x05);
        output.extend_from_slice(&(command.len() as u32).to_be_bytes());
        output.extend_from_slice(command);
    }
    output.push(output[9]);
    let checksum = crc16(&output[8..]);
    output.extend_from_slice(&(checksum as u32).to_be_bytes());
    output
}

/// Writes a Codec 12 command batch and flushes the writer.
pub fn write_codec12_commands<'a>(
    writer: &mut impl Write,
    commands: impl IntoIterator<Item = &'a [u8]>,
) -> io::Result<()> {
    writer.write_all(&encode_codec12_commands(commands))?;
    writer.flush()
}
