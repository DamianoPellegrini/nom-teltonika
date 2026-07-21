use std::io::{self, Write};

use crate::parser_impl::crc16;

/// Encodes the one-byte server decision after an IMEI handshake.
///
/// `true` produces `0x01`; `false` produces `0x00`.
pub const fn encode_imei_approval(accepted: bool) -> [u8; 1] {
    [accepted as u8]
}

/// Encodes the number of accepted TCP AVL records as a big-endian `u32`.
///
/// Acknowledgment is an application policy: pass the number of records made
/// durable or otherwise accepted, not merely the number that parsed correctly.
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
/// # Panics
///
/// Panics if the encoded frame cannot fit the Codec 12 `u32` length field.
pub fn encode_codec12_command(command: &[u8]) -> Vec<u8> {
    encode_codec12_commands([command])
}

/// Encodes a batch of arbitrary-byte Codec 12 commands in one TCP frame.
///
/// Payloads are bytes rather than strings because Codec 12 does not guarantee
/// UTF-8. The returned frame includes preamble, lengths, duplicate count, and
/// CRC and can be written directly to an open device GPRS connection.
///
/// # Panics
///
/// Panics if the iterator yields more than 255 commands, if size arithmetic
/// overflows, or if the encoded data field cannot fit its `u32` length.
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
    // Byte 9 is the leading command count. Reuse it for the required duplicate
    // count so both fields cannot diverge during encoding.
    output.push(output[9]);
    let checksum = crc16(&output[8..]);
    output.extend_from_slice(&(checksum as u32).to_be_bytes());
    output
}

/// Writes a Codec 12 command batch completely, then flushes the writer.
///
/// # Errors
///
/// Returns the first [`io::Error`] produced by `write_all` or `flush`. After a
/// write error, the peer may have received a prefix; reconnect before retrying
/// unless the transport provides a stronger recovery guarantee.
///
/// # Panics
///
/// Has the same input-size panic conditions as [`encode_codec12_commands`].
pub fn write_codec12_commands<'a>(
    writer: &mut impl Write,
    commands: impl IntoIterator<Item = &'a [u8]>,
) -> io::Result<()> {
    writer.write_all(&encode_codec12_commands(commands))?;
    writer.flush()
}
