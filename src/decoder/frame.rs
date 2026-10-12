use core::{fmt, num::NonZeroUsize};

use super::avl::{AvlPacketError, validate_avl_data};
use super::gprs::{GprsPacketError, validate_gprs_data};
use crate::checksum::crc16;
use crate::protocol::{AvlCodec, Codec, FrameView};

// TCP frame layout: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols,
// sections "Codec for device data sending > Codec 8 > AVL Data Packet" and
// "Codec for communication over GPRS messages > Codec 12 > General Codec12
// message structure" (accessed 2026-09-24). Both codec families share it:
//
// | Preamble | Data length | Data (Codec ID to second quantity) | CRC-16 |
// | 4 bytes  | 4 bytes     | `data length` bytes                | 4 bytes |

/// The preamble that starts every TCP frame: four zero bytes.
pub(crate) const FRAME_PREAMBLE: [u8; 4] = [0; 4];

/// Size of the data length field, which follows the preamble.
const DATA_LENGTH_LEN: usize = 4;

/// Size of the frame header: the preamble and the data length field.
pub(crate) const FRAME_HEADER_LEN: usize = FRAME_PREAMBLE.len() + DATA_LENGTH_LEN;

/// Size of the CRC-16 field, which is sent as a 4-byte integer.
pub(crate) const FRAME_CRC_LEN: usize = 4;

/// Bytes of a frame around its data field: the header and the CRC.
pub(crate) const FRAME_OVERHEAD: usize = FRAME_HEADER_LEN + FRAME_CRC_LEN;

/// Largest Codec 8 or Codec 8 Extended frame, counted from the preamble to
/// the CRC.
///
/// Source: <https://wiki.teltonika-gps.com/view/Codec>, sections "Codec 8"
/// and "Codec 8 Extended" (accessed 2026-10-10): "Maximum AVL packet size is
/// 1280 bytes", for all devices but FMB640, whose limit is lower. The
/// "Codec 16" section states no limit, so Codec 16 frames only have
/// [`MAX_FRAME_LEN`].
pub(crate) const MAX_CODEC8_FRAME_LEN: usize = 1280;

/// Largest frame of any codec, counted from the preamble to the CRC.
///
/// A safety bound on how much a peer can make a caller buffer, not a
/// protocol rule: Teltonika states no maximum for Codec 16 or for GPRS
/// messages (sections "Codec 12" to "Codec 17" of [Teltonika Data Sending
/// Protocols], accessed 2026-10-10), whose 4-byte data length would allow
/// 4 GiB per connection.
/// The bound is the largest length a `u16` holds, which is also the most a
/// UDP datagram's length field can declare, so no unit of either transport
/// is longer; the wiki's longest Codec 12 example is 156 bytes.
///
/// [Teltonika Data Sending Protocols]: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols
pub(crate) const MAX_FRAME_LEN: usize = u16::MAX as usize;

/// Decodes one TCP frame, AVL data or GPRS messages, moving `input` past
/// it.
///
/// Three steps, in the order of the frame's fields:
///
/// 1. Reads the header: the preamble and the length of the data field.
/// 2. Sets the data field aside, once the whole declared frame is buffered.
/// 3. Reads the CRC-16 and checks it against the data field, then validates
///    the data field for its codec.
///
/// Stops at the end of the first frame when `input` holds more. On success
/// `input` is advanced past the frame, and the result borrows from it;
/// convert it with [`FrameView::evaluate`] before the buffer is reused.
/// [`parse_frame`] is the same decoder returning the remaining bytes.
///
/// # Errors
///
/// - [`DecodeFrameError::Incomplete`] with the exact number of missing bytes
///   until the frame is fully buffered. `input` is left untouched.
/// - [`DecodeFrameError::InvalidFrame`] when the whole frame is buffered but
///   invalid: CRC mismatch, unsupported codec, or malformed data. `input` is
///   advanced past the frame, so the next one can be decoded.
/// - [`DecodeFrameError::InvalidHeader`] when the header can't delimit a
///   frame: invalid preamble, or a declared length over the size limit
///   (1280 bytes for Codec 8 and Codec 8 Extended, 65,535 for any other
///   codec). `input` is left untouched, and the next frame can't be found.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::take_frame;
/// use nom_teltonika::protocol::{AvlCodec, FrameView, Priority};
///
/// // "Codec 8 > Examples > 1st example" from the Teltonika wiki.
/// let bytes = hex::decode(
///     "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF",
/// )?;
/// let mut input = &bytes[..];
///
/// let FrameView::Avl(packet) = take_frame(&mut input)? else {
///     panic!("expected AVL data");
/// };
/// assert_eq!(packet.codec(), AvlCodec::Codec8);
/// assert_eq!(packet.records().len(), 1);
///
/// let record = packet.records().next().unwrap();
/// assert_eq!(u64::from(record.timestamp()), 1_560_161_086_000);
/// assert_eq!(record.priority(), Priority::High);
/// assert_eq!(record.io_elements().len(), 5);
/// assert!(input.is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Reading frames from a growing buffer:
///
/// ```
/// use nom_teltonika::decoder::{DecodeFrameError, take_frame};
///
/// fn next_frame(buffer: &mut Vec<u8>) -> Option<Result<(), DecodeFrameError>> {
///     let mut input = &buffer[..];
///     let result = match take_frame(&mut input) {
///         Ok(frame) => Ok(println!("{frame:?}")),
///         // Read more bytes into `buffer` and call again.
///         Err(DecodeFrameError::Incomplete { .. }) => return None,
///         // Send a negative acknowledgment and go on with the next frame.
///         Err(error @ DecodeFrameError::InvalidFrame { .. }) => Err(error),
///         // The next frame can't be found: close the connection.
///         Err(error @ DecodeFrameError::InvalidHeader(_)) => return Some(Err(error)),
///     };
///     let consumed = buffer.len() - input.len();
///     buffer.drain(..consumed);
///     Some(result)
/// }
/// # let mut buffer = vec![0, 0, 0];
/// # assert!(next_frame(&mut buffer).is_none());
/// ```
pub fn take_frame<'a>(input: &mut &'a [u8]) -> Result<FrameView<'a>, DecodeFrameError> {
    let len = frame_len(input).map_err(DecodeFrameError::InvalidHeader)?;
    let Some((frame, rest)) = input.split_at_checked(len) else {
        return Err(DecodeFrameError::Incomplete {
            needed: NonZeroUsize::new(len - input.len()).unwrap_or(NonZeroUsize::MIN),
        });
    };
    // The frame is delimited: from here on, `input` stays past it whether it
    // is accepted or rejected.
    *input = rest;
    validate_frame(frame).map_err(|reason| DecodeFrameError::InvalidFrame { len, reason })
}

/// Decodes one TCP frame, AVL data or GPRS messages, returning the bytes
/// after it.
///
/// Same as [`take_frame`], in the style of [nom](https://docs.rs/nom):
/// the input is not a cursor, and the remaining bytes come back with the
/// frame.
///
/// # Errors
///
/// Returns [`DecodeFrameError`], as [`take_frame`] does. No remaining
/// bytes are returned with an error: after
/// [`DecodeFrameError::InvalidFrame`], the next frame starts `len` bytes
/// into `input`.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::{DecodeFrameError, parse_frame};
/// use nom_teltonika::protocol::FrameView;
///
/// // "Codec 12 > GPRS commands examples", 1st example, from the Teltonika
/// // wiki, with its last CRC byte changed, and then as it is.
/// let good = hex::decode("000000000000000F0C010500000007676574696E666F0100004312")?;
/// let mut bytes = good.clone();
/// bytes[26] ^= 1;
/// bytes.extend_from_slice(&good);
///
/// let Err(DecodeFrameError::InvalidFrame { len, .. }) = parse_frame(&bytes) else {
///     panic!("expected an invalid frame");
/// };
/// let (rest, frame) = parse_frame(&bytes[len..])?;
/// assert!(matches!(frame, FrameView::Gprs(_)));
/// assert!(rest.is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_frame(input: &[u8]) -> Result<(&[u8], FrameView<'_>), DecodeFrameError> {
    let mut rest = input;
    let frame = take_frame(&mut rest)?;
    Ok((rest, frame))
}

/// Returns the length of the frame at the start of `input`, from its
/// preamble to its CRC, as far as the buffered bytes tell.
///
/// Until the header is buffered, the frame is at least a header long, and
/// that length is returned, as [`imei_len`](super::imei::imei_len) does with
/// its prefix: `input` is always shorter than such a length, so a caller
/// that compares the two waits for exactly the bytes that decide it.
///
/// The size limits are checked here, before the frame is waited for: they
/// exist so that a peer can't make the caller buffer, and then check, more
/// than a device would send. A declared length over [`MAX_FRAME_LEN`] is
/// rejected whatever the codec. One over [`MAX_CODEC8_FRAME_LEN`] is rejected
/// for Codec 8 and Codec 8 Extended ([`AvlCodec::max_frame_len`]); the codec
/// ID that tells is the first byte of the data field, so it is waited for,
/// as one byte past the header, only for a length between the two limits.
///
/// # Errors
///
/// Returns [`HeaderError`] for an invalid preamble or a declared length over
/// its limit.
pub(crate) fn frame_len(input: &[u8]) -> Result<usize, HeaderError> {
    let Some((&[p0, p1, p2, p3, l0, l1, l2, l3], body)) = input.split_first_chunk() else {
        return Ok(FRAME_HEADER_LEN);
    };
    let preamble = [p0, p1, p2, p3];
    if preamble != FRAME_PREAMBLE {
        return Err(HeaderError::InvalidPreamble { found: preamble });
    }
    // In `u64`, the total can't overflow.
    let declared = u64::from(u32::from_be_bytes([l0, l1, l2, l3])) + FRAME_OVERHEAD as u64;
    let too_long = |limit: usize| HeaderError::TooLong {
        declared,
        limit: limit as u64,
    };

    let len = match usize::try_from(declared) {
        Ok(len) if len <= MAX_FRAME_LEN => len,
        _ => return Err(too_long(MAX_FRAME_LEN)),
    };
    if len > MAX_CODEC8_FRAME_LEN {
        let Some(&codec_id) = body.first() else {
            return Ok(FRAME_HEADER_LEN + 1);
        };
        if let Ok(codec) = AvlCodec::try_from(codec_id) {
            let limit = codec.max_frame_len();
            if len > limit {
                return Err(too_long(limit));
            }
        }
    }
    Ok(len)
}

/// Checks the CRC of a frame of the length [`frame_len`] returned and
/// validates its data field for its codec.
///
/// # Errors
///
/// Returns [`FrameError`]: empty data field, unsupported codec, CRC
/// mismatch, or invalid content, checked in that order, the cheapest first:
/// the CRC of a frame that can't be decoded anyway is not computed.
///
/// # Panics
///
/// Panics if `frame` is shorter than a header and a CRC, which a length
/// from [`frame_len`] never is.
pub(crate) fn validate_frame(frame: &[u8]) -> Result<FrameView<'_>, FrameError> {
    let (data, crc) = frame
        .split_at_checked(FRAME_HEADER_LEN)
        .and_then(|(_header, body)| body.split_last_chunk::<FRAME_CRC_LEN>())
        .expect("`frame_len` counts the header and the CRC");

    let &codec_id = data.first().ok_or(FrameError::NoData)?;
    let codec = Codec::try_from(codec_id).map_err(FrameError::UnsupportedCodec)?;
    // The CRC-16 is sent as a 4-byte integer, so its upper half is zero.
    let expected = crc16(data);
    let received = u32::from_be_bytes(*crc);
    if received != u32::from(expected) {
        return Err(FrameError::CrcMismatch { expected, received });
    }
    match codec {
        Codec::Avl(codec) => validate_avl_data(codec, data)
            .map(FrameView::Avl)
            .map_err(FrameError::Avl),
        Codec::Gprs(codec) => validate_gprs_data(codec, data)
            .map(FrameView::Gprs)
            .map_err(FrameError::Gprs),
    }
}

/// The error returned by [`take_frame`] and [`parse_frame`].
///
/// The variants are the three states the input can be in: not all there,
/// delimited but invalid, or impossible to delimit. The reasons inside can
/// grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeFrameError {
    /// The declared frame is not fully buffered yet. A cursor is left
    /// untouched; buffer at least `needed` more bytes and retry.
    Incomplete {
        /// Number of bytes missing from the frame.
        needed: NonZeroUsize,
    },
    /// The frame is complete but invalid. A cursor is advanced past it, so
    /// the next frame can be decoded; the device expects a negative
    /// acknowledgment for AVL data.
    InvalidFrame {
        /// Length of the invalid frame, from its preamble to its CRC: where
        /// the next frame starts in the input.
        len: usize,
        /// Why the frame is invalid.
        reason: FrameError,
    },
    /// The header can't delimit a frame, so the next frame can't be found.
    /// A cursor is left untouched. Either the peer is not a Teltonika
    /// device or the connection is out of step with it, so closing the
    /// connection is the only safe answer; the choice stays with the
    /// caller, who may also look for the next preamble in the input.
    InvalidHeader(HeaderError),
}

impl fmt::Display for DecodeFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => {
                write!(f, "incomplete TCP frame: {needed} more byte(s) needed")
            }
            Self::InvalidFrame { .. } => f.write_str("invalid TCP frame"),
            Self::InvalidHeader(_) => f.write_str("invalid TCP frame header"),
        }
    }
}

impl core::error::Error for DecodeFrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Incomplete { .. } => None,
            Self::InvalidFrame { reason, .. } => Some(reason),
            Self::InvalidHeader(error) => Some(error),
        }
    }
}

/// Why a complete TCP frame is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// The data field is empty, so the frame has no codec ID.
    NoData,
    /// The received CRC-16 differs from the one computed over the data field.
    CrcMismatch {
        /// CRC-16 computed over the data field.
        expected: u16,
        /// CRC field as received, 4 bytes wide.
        received: u32,
    },
    /// The codec ID is not supported by this crate, such as Codec 13, 14, 15,
    /// or 17.
    UnsupportedCodec(u8),
    /// The AVL data is invalid.
    Avl(AvlPacketError),
    /// The GPRS data (Codec 12) is invalid.
    Gprs(GprsPacketError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoData => f.write_str("empty data field"),
            Self::CrcMismatch { expected, received } => write!(
                f,
                "CRC mismatch: computed {expected:#06x}, received {received:#010x}"
            ),
            Self::UnsupportedCodec(id) => write!(f, "unsupported codec {id:#04x}"),
            Self::Avl(_) => f.write_str("invalid AVL data"),
            Self::Gprs(_) => f.write_str("invalid GPRS data"),
        }
    }
}

impl core::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Avl(error) => Some(error),
            Self::Gprs(error) => Some(error),
            Self::NoData | Self::CrcMismatch { .. } | Self::UnsupportedCodec(_) => None,
        }
    }
}

/// Why a TCP frame header can't delimit a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderError {
    /// The frame doesn't start with four zero bytes.
    InvalidPreamble {
        /// The first four bytes, as received.
        found: [u8; 4],
    },
    /// The declared frame is too long: over 1280 bytes for Codec 8 and
    /// Codec 8 Extended, or over 65,535 bytes for any other codec. It is
    /// rejected from its header, without waiting for its bytes.
    ///
    /// Devices don't send frames this long, so the length field was not
    /// written by one: the peer is something else, possibly hostile, or the
    /// bytes read as a header are the middle of other data.
    TooLong {
        /// Declared frame size, from the preamble to the CRC.
        declared: u64,
        /// Size limit for the codec.
        limit: u64,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPreamble { found } => {
                write!(f, "invalid preamble {found:02x?}, expected four zero bytes")
            }
            Self::TooLong { declared, limit } => {
                write!(
                    f,
                    "declared frame size {declared} is over the limit {limit}"
                )
            }
        }
    }
}

impl core::error::Error for HeaderError {}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::decoder::tests::frame;
    use crate::fixtures::{self, CODEC8, CODEC12_COMMAND};

    /// "Codec 8 > Examples > 1st example": data length 0x36.
    fn codec8() -> Vec<u8> {
        fixtures::bytes(CODEC8)
    }

    /// "Codec 12 > GPRS commands examples": the `getinfo` command.
    fn getinfo() -> Vec<u8> {
        fixtures::bytes(CODEC12_COMMAND)
    }

    fn needed(bytes: usize) -> DecodeFrameError {
        DecodeFrameError::Incomplete {
            needed: NonZeroUsize::new(bytes).unwrap(),
        }
    }

    /// An invalid frame of `len` bytes.
    fn invalid(len: usize, reason: FrameError) -> DecodeFrameError {
        DecodeFrameError::InvalidFrame { len, reason }
    }

    #[test]
    fn measures_the_wiki_examples_from_their_header() {
        for example in [codec8(), getinfo()] {
            assert_eq!(frame_len(&example[..FRAME_HEADER_LEN]), Ok(example.len()));
        }
    }

    #[test]
    fn parse_returns_the_bytes_after_the_frame() {
        let mut buffer = codec8();
        buffer.extend_from_slice(&getinfo());

        let (rest, frame) = parse_frame(&buffer).unwrap();
        assert!(matches!(frame, FrameView::Avl(_)));
        assert_eq!(rest, getinfo());
        assert_eq!(parse_frame(&buffer[..3]).unwrap_err(), needed(5));
    }

    #[test]
    fn parse_reports_where_the_next_frame_starts_after_an_invalid_one() {
        let mut buffer = codec8();
        buffer[codec8().len() - 1] ^= 1;
        buffer.extend_from_slice(&getinfo());

        let Err(DecodeFrameError::InvalidFrame { len, .. }) = parse_frame(&buffer) else {
            panic!("expected an invalid frame");
        };
        assert_eq!(&buffer[len..], getinfo());
    }

    #[test]
    fn stops_at_the_end_of_the_first_frame() {
        let mut buffer = codec8();
        buffer.extend_from_slice(&getinfo());
        let mut input = &buffer[..];

        take_frame(&mut input).unwrap();
        assert_eq!(input, getinfo());
        assert!(matches!(take_frame(&mut input), Ok(FrameView::Gprs(_))));
        assert!(input.is_empty());
    }

    #[test]
    fn reports_the_exact_need_at_every_truncation_and_leaves_input_untouched() {
        for frame in [codec8(), getinfo()] {
            for end in 0..frame.len() {
                let mut input = &frame[..end];
                let expected = match end {
                    0..FRAME_HEADER_LEN => FRAME_HEADER_LEN - end,
                    // Declared total.
                    _ => frame.len() - end,
                };
                assert_eq!(
                    take_frame(&mut input).unwrap_err(),
                    needed(expected),
                    "truncated at {end}"
                );
                assert_eq!(input, &frame[..end]);
            }
        }
    }

    #[test]
    fn accepts_avl_frames_at_the_size_limit() {
        let mut buffer = vec![0; MAX_CODEC8_FRAME_LEN];
        let data_len = MAX_CODEC8_FRAME_LEN - FRAME_HEADER_LEN - FRAME_CRC_LEN;
        buffer[4..8].copy_from_slice(&u32::try_from(data_len).unwrap().to_be_bytes());
        buffer[8] = 0x8e;
        assert_eq!(frame_len(&buffer), Ok(MAX_CODEC8_FRAME_LEN));
    }

    /// A header declaring a frame of `len` bytes, preamble to CRC.
    fn header(len: usize) -> [u8; FRAME_HEADER_LEN] {
        let data_len = u32::try_from(len - FRAME_HEADER_LEN - FRAME_CRC_LEN).unwrap();
        let mut header = [0; FRAME_HEADER_LEN];
        header[4..].copy_from_slice(&data_len.to_be_bytes());
        header
    }

    #[test]
    fn waits_for_other_frames_up_to_their_size_limit() {
        // Codec 16, which has no documented limit, Codec 12, and an
        // unsupported codec, at the limit. The codec ID is waited for first,
        // to tell them from Codec 8 and Codec 8 Extended.
        let header = header(MAX_FRAME_LEN);
        assert_eq!(frame_len(&header), Ok(FRAME_HEADER_LEN + 1));
        assert_eq!(take_frame(&mut &header[..]).unwrap_err(), needed(1));
        for codec_id in [0x10, 0x0c, 0x0d] {
            let mut input = header.to_vec();
            input.push(codec_id);
            assert_eq!(frame_len(&input), Ok(MAX_FRAME_LEN));
            assert_eq!(
                take_frame(&mut &input[..]).unwrap_err(),
                needed(MAX_FRAME_LEN - input.len())
            );
        }
    }

    #[test]
    fn rejects_any_frame_over_the_larger_limit_from_its_header_alone() {
        for (header, declared) in [
            (header(MAX_FRAME_LEN + 1), MAX_FRAME_LEN as u64 + 1),
            (
                [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
                u64::from(u32::MAX) + 12,
            ),
        ] {
            let mut input = &header[..];
            assert_eq!(
                take_frame(&mut input).unwrap_err(),
                DecodeFrameError::InvalidHeader(HeaderError::TooLong {
                    declared,
                    limit: MAX_FRAME_LEN as u64,
                })
            );
            assert_eq!(input, header);
        }
    }

    #[test]
    fn rejects_codec8_frames_over_the_size_limit_without_waiting() {
        for codec_id in [0x08, 0x8e] {
            let data_len =
                u32::try_from(MAX_CODEC8_FRAME_LEN - FRAME_HEADER_LEN - FRAME_CRC_LEN + 1).unwrap();
            let mut header = [0; 9];
            header[4..8].copy_from_slice(&data_len.to_be_bytes());
            header[8] = codec_id;

            let mut input = &header[..];
            assert_eq!(
                take_frame(&mut input).unwrap_err(),
                DecodeFrameError::InvalidHeader(HeaderError::TooLong {
                    declared: MAX_CODEC8_FRAME_LEN as u64 + 1,
                    limit: MAX_CODEC8_FRAME_LEN as u64,
                })
            );
            assert_eq!(input, header);
        }
    }

    #[test]
    fn rejects_an_invalid_preamble_once_the_header_is_buffered() {
        let mut bytes = codec8();
        bytes[2] = 0x47;

        assert_eq!(take_frame(&mut &bytes[..7]).unwrap_err(), needed(1));
        let mut input = &bytes[..];
        assert_eq!(
            take_frame(&mut input).unwrap_err(),
            DecodeFrameError::InvalidHeader(HeaderError::InvalidPreamble {
                found: [0, 0, 0x47, 0],
            })
        );
        assert_eq!(input, bytes);
    }

    #[test]
    fn skips_a_frame_with_no_data() {
        let mut bytes = frame(&[]);
        assert_eq!(bytes.len(), 12);
        assert_eq!(take_frame(&mut &bytes[..11]).unwrap_err(), needed(1));

        bytes.extend_from_slice(&getinfo());
        let mut input = &bytes[..];
        assert_eq!(
            take_frame(&mut input).unwrap_err(),
            invalid(12, FrameError::NoData)
        );
        assert_eq!(input, getinfo());
        assert!(take_frame(&mut input).is_ok());
    }

    #[test]
    fn skips_a_frame_with_a_bad_crc() {
        let mut bytes = codec8();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        bytes.extend_from_slice(&getinfo());

        let mut input = &bytes[..];
        assert_eq!(
            take_frame(&mut input).unwrap_err(),
            invalid(
                codec8().len(),
                FrameError::CrcMismatch {
                    expected: 0xc7cf,
                    received: 0xc7ce,
                }
            )
        );
        assert_eq!(input, getinfo());
    }

    #[test]
    fn skips_a_frame_with_an_unsupported_codec_without_checking_its_crc() {
        // A Codec 13 frame (Data Sending Protocols, "Codec 13"): delimited by
        // its header, so it can be skipped whole. Its CRC is wrong, and not
        // the reason given.
        let mut bytes = frame(&[0x0d, 0x01, 0x06, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4, 0x01]);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let mut input = &bytes[..];
        assert_eq!(
            take_frame(&mut input).unwrap_err(),
            invalid(bytes.len(), FrameError::UnsupportedCodec(0x0d))
        );
        assert!(input.is_empty());
    }

    #[test]
    fn passes_content_errors_through_and_skips_the_frame() {
        let bytes = frame(&[0x08, 0x00, 0x00]);
        let mut input = &bytes[..];
        assert_eq!(
            take_frame(&mut input).unwrap_err(),
            invalid(bytes.len(), FrameError::Avl(AvlPacketError::NoRecords))
        );
        assert!(input.is_empty());

        let bytes = frame(&[0x0c, 0x00, 0x00]);
        let mut input = &bytes[..];
        assert_eq!(
            take_frame(&mut input).unwrap_err(),
            invalid(bytes.len(), FrameError::Gprs(GprsPacketError::NoMessages))
        );
        assert!(input.is_empty());
    }

    #[test]
    fn errors_chain_their_sources() {
        use core::error::Error;
        use std::string::ToString;

        let error = invalid(66, FrameError::Avl(AvlPacketError::InvalidPriority(3)));
        let chain: Vec<_> =
            core::iter::successors(Some(&error as &dyn Error), |&error| error.source())
                .map(ToString::to_string)
                .collect();
        assert_eq!(
            chain,
            [
                "invalid TCP frame",
                "invalid AVL data",
                "invalid priority 0x03"
            ]
        );
    }
}
