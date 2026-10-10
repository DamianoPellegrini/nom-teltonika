use crate::decoder::DATAGRAM_NOT_USABLE;
use crate::protocol::DatagramIds;

// Sources: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols,
// section "Codec for device data sending > Codec 8 > Communication with
// server", and https://wiki.teltonika-gps.com/view/Codec, section "Codec 8 >
// Codec8 protocol sending over UDP" (accessed 2026-09-24).

/// Encodes the server's answer to the IMEI handshake.
///
/// "If yes, server will reply to module 01, if not – 00", as one binary byte.
///
/// # Examples
///
/// ```
/// use nom_teltonika::encoder::encode_imei_approval;
///
/// assert_eq!(encode_imei_approval(true), [0x01]);
/// assert_eq!(encode_imei_approval(false), [0x00]);
/// ```
pub const fn encode_imei_approval(accepted: bool) -> [u8; 1] {
    [accepted as u8]
}

/// Encodes the acknowledgment of a TCP AVL packet: the number of accepted
/// records as a big-endian `u32`.
///
/// Pass the number of records your application has accepted (for example,
/// stored), not merely the number that decoded.
///
/// # Examples
///
/// ```
/// use nom_teltonika::encoder::encode_avl_ack;
///
/// assert_eq!(encode_avl_ack(2), [0, 0, 0, 2]);
/// ```
pub const fn encode_avl_ack(accepted_records: u32) -> [u8; 4] {
    accepted_records.to_be_bytes()
}

/// Encodes the negative acknowledgment of a TCP AVL packet: zero accepted
/// records.
///
/// # Examples
///
/// ```
/// use nom_teltonika::encoder::encode_avl_nack;
///
/// assert_eq!(encode_avl_nack(), [0; 4]);
/// ```
pub const fn encode_avl_nack() -> [u8; 4] {
    encode_avl_ack(0)
}

/// Encodes the acknowledgment of a UDP datagram.
///
/// The IDs come from the received datagram, so an acknowledgment can't be
/// correlated with the wrong packet. Layout: length `0x0005`, packet ID,
/// `0x01`, AVL packet ID, number of accepted records.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::take_datagram;
/// use nom_teltonika::encoder::encode_udp_ack;
///
/// // "Codec 8 > Codec8 protocol sending over UDP > Example" from the
/// // Teltonika wiki, and its server response `0005CAFE010501`.
/// let bytes = hex::decode(
///     "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001",
/// )?;
/// let datagram = take_datagram(&mut &bytes[..])?;
/// assert_eq!(
///     encode_udp_ack(datagram.ids(), 1),
///     [0x00, 0x05, 0xca, 0xfe, 0x01, 0x05, 0x01]
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub const fn encode_udp_ack(ids: DatagramIds, accepted_records: u8) -> [u8; 7] {
    // The acknowledgment's own length field: the five bytes after it.
    let [len_high, len_low] = 5u16.to_be_bytes();
    let [id_high, id_low] = ids.packet_id().to_be_bytes();
    [
        len_high,
        len_low,
        id_high,
        id_low,
        DATAGRAM_NOT_USABLE,
        ids.avl_packet_id(),
        accepted_records,
    ]
}
