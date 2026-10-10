use core::{fmt, num::NonZeroUsize};

use crate::protocol::{ImeiError, ImeiView};

/// Size of the length prefix of the IMEI.
pub(crate) const IMEI_PREFIX_LEN: usize = 2;

/// Decodes the length-prefixed ASCII IMEI sent at the start of a TCP
/// session, moving `input` past it.
///
/// The handshake is a 2-byte big-endian length, then that many ASCII bytes
/// of IMEI text ("First comes a short identifying the number of bytes
/// written and then goes IMEI as text (bytes)", [Teltonika Data Sending
/// Protocols], section "Codec 8 > Communication with server"). The declared
/// length is honored, whatever it is: real IMEIs are 15 digits, but the
/// decoder doesn't require it.
///
/// On success `input` is advanced past the IMEI, and the result borrows from
/// it; convert it with [`ImeiView::evaluate`] before the buffer is reused.
/// [`parse_imei`] is the same decoder returning the remaining bytes.
///
/// # Errors
///
/// - [`DecodeImeiError::Incomplete`] with the exact number of missing bytes
///   until the 2-byte prefix, and then the declared text, are buffered.
///   `input` is left untouched.
/// - [`DecodeImeiError::NotAscii`] when the whole handshake is buffered but
///   its text is not ASCII. `input` is advanced past the handshake.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::{DecodeImeiError, take_imei};
///
/// let mut input: &[u8] = b"\x00\x0f356307042441013next";
/// let imei = take_imei(&mut input)?;
/// assert_eq!(imei.as_str(), "356307042441013");
/// assert_eq!(input, b"next");
///
/// let mut input: &[u8] = b"\x00\x0f3563";
/// assert!(matches!(
///     take_imei(&mut input),
///     Err(DecodeImeiError::Incomplete { needed }) if needed.get() == 11
/// ));
/// # Ok::<(), DecodeImeiError>(())
/// ```
///
/// [Teltonika Data Sending Protocols]: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols
pub fn take_imei<'a>(input: &mut &'a [u8]) -> Result<ImeiView<'a>, DecodeImeiError> {
    let len = imei_len(input);
    let Some((handshake, rest)) = input.split_at_checked(len) else {
        return Err(DecodeImeiError::Incomplete {
            needed: NonZeroUsize::new(len - input.len()).unwrap_or(NonZeroUsize::MIN),
        });
    };
    // The handshake is delimited by its prefix: from here on, `input` stays
    // past it whether the text is accepted or not.
    *input = rest;
    ImeiView::try_from(&handshake[IMEI_PREFIX_LEN..]).map_err(DecodeImeiError::NotAscii)
}

/// Decodes the length-prefixed ASCII IMEI sent at the start of a TCP
/// session, returning the bytes after it.
///
/// Same as [`take_imei`], in the style of [nom](https://docs.rs/nom): the
/// input is not a cursor, and the remaining bytes come back with the IMEI.
///
/// # Errors
///
/// Returns [`DecodeImeiError`], as [`take_imei`] does. No remaining bytes
/// are returned with an error.
///
/// # Examples
///
/// ```
/// use nom_teltonika::decoder::parse_imei;
///
/// let (rest, imei) = parse_imei(b"\x00\x0f356307042441013next")?;
/// assert_eq!(imei.as_str(), "356307042441013");
/// assert_eq!(rest, b"next");
/// # Ok::<(), nom_teltonika::decoder::DecodeImeiError>(())
/// ```
pub fn parse_imei(input: &[u8]) -> Result<(&[u8], ImeiView<'_>), DecodeImeiError> {
    let mut rest = input;
    let imei = take_imei(&mut rest)?;
    Ok((rest, imei))
}

/// Returns the length of the handshake at the start of `input`, prefix
/// included, as far as the buffered bytes tell.
///
/// Until the prefix is buffered, the handshake is at least a prefix long,
/// and that length is returned: `input` is always shorter than it, so a
/// caller that compares the two waits for the prefix first.
pub(crate) fn imei_len(input: &[u8]) -> usize {
    match input.first_chunk::<IMEI_PREFIX_LEN>() {
        Some(prefix) => IMEI_PREFIX_LEN + usize::from(u16::from_be_bytes(*prefix)),
        None => IMEI_PREFIX_LEN,
    }
}

/// The error returned by [`take_imei`] and [`parse_imei`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeImeiError {
    /// The handshake is not fully buffered yet. A cursor is left untouched;
    /// buffer at least `needed` more bytes and retry.
    Incomplete {
        /// Number of bytes missing from the handshake.
        needed: NonZeroUsize,
    },
    /// The handshake is complete but its text is not ASCII. A cursor is
    /// advanced past it.
    NotAscii(ImeiError),
}

impl fmt::Display for DecodeImeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => {
                write!(f, "incomplete IMEI handshake: {needed} more byte(s) needed")
            }
            Self::NotAscii(_) => f.write_str("IMEI is not ASCII"),
        }
    }
}

impl core::error::Error for DecodeImeiError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NotAscii(error) => Some(error),
            Self::Incomplete { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Handshake example from https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols,
    /// section "Codec for device data sending > Codec 8 > Communication with
    /// server" (accessed 2026-09-24).
    const HANDSHAKE: &[u8] = b"\x00\x0f356307042441013";

    fn needed(bytes: usize) -> DecodeImeiError {
        DecodeImeiError::Incomplete {
            needed: NonZeroUsize::new(bytes).unwrap(),
        }
    }

    #[test]
    fn decodes_the_wiki_handshake_and_advances_past_it() {
        let mut input = HANDSHAKE;
        assert_eq!(take_imei(&mut input).unwrap().as_str(), "356307042441013");
        assert!(input.is_empty());
    }

    #[test]
    fn honors_a_declared_length_other_than_fifteen() {
        let mut input: &[u8] = b"\x00\x0512345\x00";
        assert_eq!(take_imei(&mut input).unwrap().as_str(), "12345");
        assert_eq!(input, b"\x00");

        let mut empty: &[u8] = b"\x00\x00";
        assert_eq!(take_imei(&mut empty).unwrap().as_str(), "");
    }

    #[test]
    fn honors_the_longest_declared_length() {
        let mut handshake = std::vec![b'1'; IMEI_PREFIX_LEN + usize::from(u16::MAX)];
        handshake[..IMEI_PREFIX_LEN].copy_from_slice(&u16::MAX.to_be_bytes());
        let mut input = &handshake[..];
        assert_eq!(take_imei(&mut input).unwrap().len(), usize::from(u16::MAX));
        assert!(input.is_empty());
    }

    #[test]
    fn rejects_non_ascii_text_and_skips_the_handshake() {
        let mut input: &[u8] = b"\x00\x0335\xe9next";
        assert_eq!(
            take_imei(&mut input).unwrap_err(),
            DecodeImeiError::NotAscii(ImeiError { index: 2 })
        );
        assert_eq!(input, b"next");
    }

    #[test]
    fn parse_returns_the_bytes_after_the_handshake() {
        let (rest, imei) = parse_imei(b"\x00\x0512345\x00").unwrap();
        assert_eq!(imei.as_str(), "12345");
        assert_eq!(rest, b"\x00");
        assert_eq!(parse_imei(b"\x00").unwrap_err(), needed(1));
    }

    #[test]
    fn reports_the_exact_need_at_every_truncation_and_leaves_input_untouched() {
        for end in 0..HANDSHAKE.len() {
            let mut input = &HANDSHAKE[..end];
            assert_eq!(
                take_imei(&mut input).unwrap_err(),
                needed(if end < 2 {
                    2 - end
                } else {
                    HANDSHAKE.len() - end
                }),
                "truncated at {end}"
            );
            assert_eq!(input, &HANDSHAKE[..end]);
        }
    }
}
