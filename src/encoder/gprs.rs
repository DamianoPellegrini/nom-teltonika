#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use super::{put, put_frame};
use crate::decoder::{FRAME_OVERHEAD, MAX_FRAME_LEN, MESSAGE_HEADER_LEN};
use crate::protocol::{GprsCodec, GprsMessageType};

// Layout: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols,
// section "Codec for communication over GPRS messages > Codec 12 > General
// Codec12 message structure" (accessed 2026-09-24):
//
// | Preamble | Data size | Codec ID | Quantity 1 | (Type | Size | Payload)* | Quantity 2 | CRC-16 |
// | 4 bytes  | 4 bytes   | 1 byte   | 1 byte     | 1 + 4 + X bytes each    | 1 byte     | 4 bytes |

/// Bytes of the data field around the messages: codec ID and the two
/// quantities.
const DATA_OVERHEAD: usize = 1 + 1 + 1;

/// Encodes GPRS messages of one type into a Codec 12 frame in `out` and
/// returns the frame length.
///
/// Messages are arbitrary bytes, usually ASCII text such as `getinfo`. The
/// frame holds every message in order, with the type byte of `kind`, both
/// quantities, and the CRC. A server sends [`GprsMessageType::Command`]
/// over an open GPRS session; [`GprsMessageType::Response`] is what a device
/// sends back, to simulate one. The frame always decodes back with
/// [`take_frame`](crate::decoder::take_frame).
///
/// # Errors
///
/// Returns [`EncodeGprsError::BufferTooSmall`] with the frame length when
/// `out` can't hold the frame, and the other variants when the messages
/// can't form a frame. `out` is left unchanged on error.
///
/// # Examples
///
/// ```
/// use nom_teltonika::encoder::encode_gprs_frame_into;
/// use nom_teltonika::protocol::GprsMessageType;
///
/// let mut buffer = [0; 64];
/// let len = encode_gprs_frame_into(GprsMessageType::Command, &["getinfo"], &mut buffer)?;
/// // "Codec 12 > GPRS commands examples", 1st example, from the Teltonika wiki.
/// assert_eq!(
///     buffer[..len],
///     hex::decode("000000000000000F0C010500000007676574696E666F0100004312")?
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encode_gprs_frame_into<M: AsRef<[u8]>>(
    kind: GprsMessageType,
    messages: &[M],
    out: &mut [u8],
) -> Result<usize, EncodeGprsError> {
    let len = checked_frame_len(messages)?;
    let Some(frame) = out.get_mut(..len) else {
        return Err(EncodeGprsError::BufferTooSmall { needed: len });
    };
    put_messages(frame, kind, messages);
    Ok(len)
}

/// Encodes GPRS messages of one type into a new Codec 12 frame.
///
/// See [`encode_gprs_frame_into`] for the layout.
///
/// # Errors
///
/// Returns [`EncodeGprsError`] when the messages can't form a frame.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::take_frame;
/// use nom_teltonika::encoder::encode_gprs_frame;
/// use nom_teltonika::protocol::{FrameView, GprsMessageType};
///
/// let frame = encode_gprs_frame(GprsMessageType::Command, &["getinfo", "getio"])?;
/// assert_eq!(frame.len(), 12 + 3 + (5 + 7) + (5 + 5));
///
/// let frame = encode_gprs_frame(GprsMessageType::Response, &["DI1:1 DI2:0"])?;
/// let FrameView::Gprs(packet) = take_frame(&mut &frame[..])? else {
///     panic!("expected a GPRS frame");
/// };
/// let message = packet.messages().next().unwrap();
/// assert_eq!(message.kind(), GprsMessageType::Response);
/// assert_eq!(message.payload(), b"DI1:1 DI2:0");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "alloc")]
pub fn encode_gprs_frame<M: AsRef<[u8]>>(
    kind: GprsMessageType,
    messages: &[M],
) -> Result<Vec<u8>, EncodeGprsError> {
    let mut frame = alloc::vec![0; checked_frame_len(messages)?];
    put_messages(&mut frame, kind, messages);
    Ok(frame)
}

/// Writes the frame holding `messages` into `frame`, which has the length
/// [`checked_frame_len`] returned.
fn put_messages<M: AsRef<[u8]>>(frame: &mut [u8], kind: GprsMessageType, messages: &[M]) {
    let count = u8::try_from(messages.len()).expect("`checked_frame_len` checked the count");
    put_frame(frame, |out| {
        put(out, &[u8::from(GprsCodec::Codec12), count]);
        for message in messages {
            let message = message.as_ref();
            let size = u32::try_from(message.len()).expect("the frame is at most 65,535 bytes");
            put(out, &[u8::from(kind)]);
            put(out, &size.to_be_bytes());
            put(out, message);
        }
        put(out, &[count]);
    });
}

/// Returns the length of the frame holding `messages`, from its preamble to
/// its CRC, checking that they can form one.
///
/// # Errors
///
/// Returns [`EncodeGprsError::NoMessages`],
/// [`EncodeGprsError::TooManyMessages`], or [`EncodeGprsError::FrameTooLong`].
fn checked_frame_len<M: AsRef<[u8]>>(messages: &[M]) -> Result<usize, EncodeGprsError> {
    if messages.is_empty() {
        return Err(EncodeGprsError::NoMessages);
    }
    // Both quantities are single bytes.
    let limit = usize::from(u8::MAX);
    if messages.len() > limit {
        return Err(EncodeGprsError::TooManyMessages {
            count: messages.len(),
            limit,
        });
    }
    let len = messages
        .iter()
        .fold(FRAME_OVERHEAD + DATA_OVERHEAD, |len, message| {
            len.saturating_add(MESSAGE_HEADER_LEN)
                .saturating_add(message.as_ref().len())
        });
    if len > MAX_FRAME_LEN {
        return Err(EncodeGprsError::FrameTooLong {
            len,
            limit: MAX_FRAME_LEN,
        });
    }
    Ok(len)
}

/// The error returned when encoding GPRS messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeGprsError {
    /// There are no messages.
    NoMessages,
    /// There are more messages than the one-byte quantities can count.
    TooManyMessages {
        /// Number of messages given.
        count: usize,
        /// Largest number of messages in a frame.
        limit: usize,
    },
    /// The frame is longer than the decoder accepts: over 65,535 bytes.
    FrameTooLong {
        /// Frame length, saturated at `usize::MAX`.
        len: usize,
        /// Largest frame length.
        limit: usize,
    },
    /// The output buffer is shorter than the frame.
    BufferTooSmall {
        /// Frame length.
        needed: usize,
    },
}

impl fmt::Display for EncodeGprsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMessages => f.write_str("no GPRS message to encode"),
            Self::TooManyMessages { count, limit } => {
                write!(f, "{count} GPRS messages are over the limit {limit}")
            }
            Self::FrameTooLong { len, limit } => {
                write!(f, "GPRS frame length {len} is over the limit {limit}")
            }
            Self::BufferTooSmall { needed } => {
                write!(f, "output buffer is shorter than the {needed}-byte frame")
            }
        }
    }
}

impl core::error::Error for EncodeGprsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::take_frame;
    use crate::fixtures::{CODEC12_COMMAND, CODEC12_GETIO_COMMAND, CODEC12_GETIO_RESPONSE, bytes};
    use crate::protocol::FrameView;

    fn commands_into<M: AsRef<[u8]>>(
        commands: &[M],
        out: &mut [u8],
    ) -> Result<usize, EncodeGprsError> {
        encode_gprs_frame_into(GprsMessageType::Command, commands, out)
    }

    #[test]
    fn matches_the_wiki_examples() {
        for (command, expected) in [
            ("getinfo", CODEC12_COMMAND),
            ("getio", CODEC12_GETIO_COMMAND),
        ] {
            let mut buffer = [0; 32];
            let len = commands_into(&[command], &mut buffer).unwrap();
            assert_eq!(buffer[..len], bytes(expected));
        }
    }

    #[test]
    fn matches_the_wiki_response_example() {
        let text = "DI1:1 DI2:0 DI3:0 AIN1:0 AIN2:16924 DO1:0 DO2:1";
        let mut buffer = [0; 128];
        let len = encode_gprs_frame_into(GprsMessageType::Response, &[text], &mut buffer).unwrap();
        assert_eq!(buffer[..len], bytes(CODEC12_GETIO_RESPONSE));
    }

    #[test]
    fn encodes_a_batch_that_decodes_back() {
        let commands: [&[u8]; 3] = [b"getinfo", &[0xff, 0x00], b""];
        let mut buffer = [0; 64];
        let len = commands_into(&commands, &mut buffer).unwrap();

        let Ok(FrameView::Gprs(packet)) = take_frame(&mut &buffer[..len]) else {
            panic!("expected a Codec 12 frame");
        };
        let payloads: std::vec::Vec<_> =
            packet.messages().map(|message| message.payload()).collect();
        assert_eq!(payloads, commands);
        assert_eq!(buffer[9], 3);
        assert_eq!(buffer[len - 5], 3);
    }

    #[test]
    fn writes_nothing_into_a_short_buffer() {
        let mut buffer = [0xaa; 26];
        assert_eq!(
            commands_into(&["getinfo"], &mut buffer),
            Err(EncodeGprsError::BufferTooSmall { needed: 27 })
        );
        assert_eq!(buffer, [0xaa; 26]);
    }

    #[test]
    fn rejects_batches_that_cant_form_a_frame() {
        let none: [&str; 0] = [];
        assert_eq!(
            commands_into(&none, &mut []),
            Err(EncodeGprsError::NoMessages)
        );
        assert_eq!(
            commands_into(&[""; 256], &mut []),
            Err(EncodeGprsError::TooManyMessages {
                count: 256,
                limit: 255
            })
        );
    }

    /// Returns 255 messages that share one allocation and fill a frame of
    /// `len` bytes.
    fn messages_filling(backing: &[u8], len: usize) -> std::vec::Vec<&[u8]> {
        let payload = len - FRAME_OVERHEAD - DATA_OVERHEAD - 255 * MESSAGE_HEADER_LEN;
        let (each, rest) = (payload / 255, payload % 255);
        (0..255)
            .map(|index| &backing[..each + usize::from(index < rest)])
            .collect()
    }

    #[test]
    fn measures_frames_up_to_the_limit() {
        let backing = std::vec![0; MAX_FRAME_LEN / 255 + 1];
        let at_limit = messages_filling(&backing, MAX_FRAME_LEN);
        assert_eq!(checked_frame_len(&at_limit), Ok(MAX_FRAME_LEN));

        let over = messages_filling(&backing, MAX_FRAME_LEN + 1);
        assert_eq!(
            commands_into(&over, &mut []),
            Err(EncodeGprsError::FrameTooLong {
                len: MAX_FRAME_LEN + 1,
                limit: MAX_FRAME_LEN
            })
        );
    }
}
