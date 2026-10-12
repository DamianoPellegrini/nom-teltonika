use core::fmt;

use crate::protocol::{GprsCodec, GprsMessageType, GprsMessageView, GprsPacketView};

// Layout: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols,
// section "Codec for communication over GPRS messages > Codec 12 > General
// Codec12 message structure" (accessed 2026-09-24). The data field runs from
// the codec ID to the second quantity:
//
// | Codec ID | Quantity 1 | Type   | Size    | Payload | ... | Quantity 2 |
// | 1 byte   | 1 byte     | 1 byte | 4 bytes | X bytes | ... | 1 byte     |

/// Bytes of a message before its payload: type (1) and size (4).
pub(crate) const MESSAGE_HEADER_LEN: usize = 1 + 4;

/// Validates the data field of a GPRS frame, from the codec ID to the
/// second quantity.
///
/// The first quantity gives the number of messages to read. The second must
/// be there, as the one byte after them, but its value is not read: the wiki
/// says it "will not be parsed" and only recommends that it "should contain
/// the same value" as the first, unlike the second record count of AVL data,
/// which "must be the same".
///
/// # Errors
///
/// Returns [`GprsPacketError`] for the first invalid message,
/// [`GprsPacketError::NoMessages`] if the first quantity is zero,
/// [`GprsPacketError::Truncated`] if the second is missing, and
/// [`GprsPacketError::TrailingBytes`] if bytes follow it.
pub(crate) fn validate_gprs_data(
    codec: GprsCodec,
    data: &[u8],
) -> Result<GprsPacketView<'_>, GprsPacketError> {
    let (&[_codec_id, count], start) =
        data.split_first_chunk().ok_or(GprsPacketError::Truncated)?;
    if count == 0 {
        return Err(GprsPacketError::NoMessages);
    }
    let mut rest = start;
    for _ in 0..count {
        take_message(&mut rest)?;
    }
    let messages = &start[..start.len() - rest.len()];
    match *rest {
        [] => Err(GprsPacketError::Truncated),
        [_second] => Ok(GprsPacketView {
            codec,
            count,
            messages,
        }),
        _ => Err(GprsPacketError::TrailingBytes),
    }
}

/// Reads one GPRS message, moving `input` past it: type, size, and payload.
///
/// # Errors
///
/// Returns [`GprsPacketError::InvalidMessageType`] for an unknown type
/// byte and [`GprsPacketError::Truncated`] if the type, the size, or the
/// declared payload runs past `input`. `input` is left untouched.
pub(crate) fn take_message<'a>(
    input: &mut &'a [u8],
) -> Result<GprsMessageView<'a>, GprsPacketError> {
    let (&[kind, s0, s1, s2, s3], rest) = input
        .split_first_chunk::<MESSAGE_HEADER_LEN>()
        .ok_or(GprsPacketError::Truncated)?;
    let kind = GprsMessageType::try_from(kind).map_err(GprsPacketError::InvalidMessageType)?;
    // A size that doesn't fit in `usize` can't fit in the data field either.
    let size = usize::try_from(u32::from_be_bytes([s0, s1, s2, s3])).unwrap_or(usize::MAX);
    let (payload, rest) = rest
        .split_at_checked(size)
        .ok_or(GprsPacketError::Truncated)?;
    *input = rest;
    Ok(GprsMessageView { kind, payload })
}

/// The error returned when the data of a GPRS frame is invalid.
///
/// The frame was fully delimited, so the error concerns only its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GprsPacketError {
    /// The data ends before a message that the first quantity declares, a
    /// payload that a size declares, or the second quantity.
    Truncated,
    /// The first quantity is zero: the data holds no message.
    NoMessages,
    /// Bytes remain after the second quantity.
    TrailingBytes,
    /// A message's type byte is not a [`GprsMessageType`].
    ///
    /// [`GprsMessageType`]: crate::protocol::GprsMessageType
    InvalidMessageType(u8),
}

impl fmt::Display for GprsPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("GPRS data ends before its declared end"),
            Self::NoMessages => f.write_str("GPRS packet holds no message"),
            Self::TrailingBytes => f.write_str("bytes after the second quantity"),
            Self::InvalidMessageType(byte) => write!(f, "invalid message type {byte:#04x}"),
        }
    }
}

impl core::error::Error for GprsPacketError {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::GprsPacketError;
    use crate::decoder::take_frame;
    use crate::decoder::tests::frame;
    use crate::fixtures;
    use crate::protocol::{FrameView, GprsCodec, GprsMessageType, GprsPacketView};

    // The expected text of each wiki example is the wiki's own "converted
    // from HEX to ASCII" note.
    const GETINFO_COMMAND: &str = fixtures::CODEC12_COMMAND;
    const GETINFO_RESPONSE: &str = fixtures::CODEC12_GETINFO_RESPONSE;
    const GETIO_COMMAND: &str = fixtures::CODEC12_GETIO_COMMAND;
    const GETIO_RESPONSE: &str = fixtures::CODEC12_GETIO_RESPONSE;

    fn codec12_packet(bytes: &[u8]) -> GprsPacketView<'_> {
        let mut input = bytes;
        let FrameView::Gprs(packet) = take_frame(&mut input).unwrap() else {
            panic!("expected a GPRS frame");
        };
        assert!(input.is_empty());
        assert_eq!(packet.codec(), GprsCodec::Codec12);
        packet
    }

    fn messages(packet: GprsPacketView<'_>) -> Vec<(GprsMessageType, &[u8])> {
        packet
            .messages()
            .map(|message| (message.kind(), message.payload()))
            .collect()
    }

    #[test]
    fn decodes_the_wiki_examples() {
        for (hex, kind, text) in [
            (GETINFO_COMMAND, GprsMessageType::Command, "getinfo"),
            (
                GETINFO_RESPONSE,
                GprsMessageType::Response,
                "INI:2019/7/22 7:22 RTC:2019/7/22 7:53 RST:2 ERR:1 SR:0 BR:0 CF:0 FG:0 FL:0 TU:0/0 UT:0 SMS:0 NOGPS:0:30 GPS:1 SAT:0 RS:3 RF:65 SF:1 MD:0",
            ),
            (GETIO_COMMAND, GprsMessageType::Command, "getio"),
            (
                GETIO_RESPONSE,
                GprsMessageType::Response,
                "DI1:1 DI2:0 DI3:0 AIN1:0 AIN2:16924 DO1:0 DO2:1",
            ),
        ] {
            let bytes = hex::decode(hex).unwrap();
            let packet = codec12_packet(&bytes);
            assert_eq!(messages(packet), [(kind, text.as_bytes())]);
        }
    }

    #[test]
    fn ignores_the_value_of_the_second_quantity() {
        // One command, "a", between Quantity 1 = 1 and Quantity 2 = 9: the
        // wiki says Quantity 2 "will not be parsed".
        let data = [0x0c, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, b'a', 0x09];
        let packet = super::validate_gprs_data(GprsCodec::Codec12, &data).unwrap();
        assert_eq!(messages(packet), [(GprsMessageType::Command, &b"a"[..])]);
    }

    #[test]
    fn rejects_a_first_quantity_that_differs_from_the_messages_held() {
        // Two messages declared, one held: the second quantity is read as a
        // message type.
        let command = [0x05, 0x00, 0x00, 0x00, 0x01, b'a'];
        let more = [&[0x0c, 0x02][..], &command, &[0x05]].concat();
        assert_eq!(error(&more), GprsPacketError::Truncated);

        // One message declared, two held.
        let fewer = [&[0x0c, 0x01][..], &command, &command, &[0x01]].concat();
        assert_eq!(error(&fewer), GprsPacketError::TrailingBytes);
    }

    #[test]
    fn decodes_several_messages_of_mixed_types() {
        let data = [
            0x0c, 0x03, // codec ID, Quantity 1
            0x05, 0x00, 0x00, 0x00, 0x01, b'a', // command "a"
            0x06, 0x00, 0x00, 0x00, 0x02, b'b', b'c', // response "bc"
            0x05, 0x00, 0x00, 0x00, 0x00, // empty command
            0x03, // Quantity 2
        ];
        let bytes = frame(&data);
        let packet = codec12_packet(&bytes);

        assert_eq!(packet.messages().len(), 3);
        assert_eq!(
            messages(packet),
            [
                (GprsMessageType::Command, &b"a"[..]),
                (GprsMessageType::Response, &b"bc"[..]),
                (GprsMessageType::Command, &b""[..]),
            ]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn evaluated_packet_matches_its_view() {
        use crate::protocol::GprsPacket;

        let bytes = hex::decode(GETIO_RESPONSE).unwrap();
        let view = codec12_packet(&bytes);
        let packet = GprsPacket::from(view);
        assert_eq!(packet.codec(), GprsCodec::Codec12);

        assert_eq!(packet.messages().len(), 1);
        assert_eq!(packet.messages()[0].kind(), GprsMessageType::Response);
        assert_eq!(
            packet.messages()[0].payload(),
            view.messages().next().unwrap().payload()
        );
    }

    fn error(data: &[u8]) -> GprsPacketError {
        super::validate_gprs_data(GprsCodec::Codec12, data).unwrap_err()
    }

    #[test]
    fn rejects_data_that_ends_early() {
        // `getinfo` data field.
        let data = [
            0x0c, 0x01, 0x05, 0x00, 0x00, 0x00, 0x07, b'g', b'e', b't', b'i', b'n', b'f', b'o',
            0x01,
        ];
        for end in 1..data.len() {
            assert_eq!(
                error(&data[..end]),
                GprsPacketError::Truncated,
                "truncated at {end}"
            );
        }
    }

    #[test]
    fn rejects_zero_messages() {
        assert_eq!(error(&[0x0c, 0x00, 0x00]), GprsPacketError::NoMessages);
    }

    #[test]
    fn rejects_every_message_type_but_command_and_response() {
        // The wiki allows only 0x05 and 0x06: "Codec 12 > General Codec12
        // message structure".
        for value in 0..=u8::MAX {
            let data = [0x0c, 0x01, value, 0x00, 0x00, 0x00, 0x00, 0x01];
            let decoded = super::validate_gprs_data(GprsCodec::Codec12, &data)
                .map(|packet| packet.messages().next().unwrap().kind());
            let expected =
                GprsMessageType::try_from(value).map_err(GprsPacketError::InvalidMessageType);
            assert_eq!(decoded, expected);
            assert_eq!(
                decoded.is_ok(),
                matches!(value, 0x05 | 0x06),
                "{value:#04x}"
            );
        }
    }

    #[test]
    fn decodes_as_many_messages_as_the_quantity_can_declare() {
        let mut data = std::vec![0x0c, u8::MAX];
        for _ in 0..u8::MAX {
            data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
        }
        data.push(u8::MAX);
        let packet = super::validate_gprs_data(GprsCodec::Codec12, &data).unwrap();
        assert_eq!(packet.messages().len(), 255);
    }

    #[test]
    fn rejects_a_size_past_the_end() {
        assert_eq!(
            error(&[0x0c, 0x01, 0x05, 0xff, 0xff, 0xff, 0xff, b'a', 0x01]),
            GprsPacketError::Truncated
        );
    }
}
