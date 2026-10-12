#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::{borrow::Borrow, fmt, ops::Deref};

/// A validated IMEI borrowed from the buffer it was decoded from.
///
/// The text is ASCII. Its length and digits are not checked: real IMEIs are
/// 15 decimal digits, but the TCP handshake declares its own length
/// ([Teltonika Data Sending Protocols], section "Codec 8 > Communication with
/// server"). Convert it into an [`Imei`] with [`evaluate`](Self::evaluate)
/// when it must outlive the buffer.
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::ImeiView;
///
/// let imei = ImeiView::try_from("356307042441013").unwrap();
/// assert_eq!(imei.as_str(), "356307042441013");
/// assert!(ImeiView::try_from("35630704244101é").is_err());
/// ```
///
/// [Teltonika Data Sending Protocols]: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImeiView<'a>(&'a str);

#[cfg(feature = "alloc")]
/// A validated IMEI that owns its text.
///
/// Obtained from an [`ImeiView`] with [`ImeiView::evaluate`] or [`From`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Imei(Box<str>);

impl<'a> ImeiView<'a> {
    /// Returns the validated ASCII text, borrowed from the decoded buffer.
    pub const fn as_str(self) -> &'a str {
        self.0
    }

    #[cfg(feature = "alloc")]
    /// Copies the text into an [`Imei`] that outlives the decoded buffer.
    pub fn evaluate(self) -> Imei {
        Imei(self.0.into())
    }
}

#[cfg(feature = "alloc")]
impl Imei {
    /// Returns the validated ASCII text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for ImeiView<'a> {
    type Error = ImeiError;

    /// Validates that `text` is ASCII and wraps it without copying.
    ///
    /// # Errors
    ///
    /// Returns [`ImeiError`] with the index of the first non-ASCII byte.
    fn try_from(text: &'a [u8]) -> Result<Self, Self::Error> {
        // `is_ascii` is vectorized; search for the offending byte only once
        // we know there is one.
        if !text.is_ascii() {
            let index = text
                .iter()
                .position(|byte| !byte.is_ascii())
                .expect("`is_ascii` returned false, so some byte is not ASCII");
            return Err(ImeiError { index });
        }
        // SAFETY: every byte of `text` is ASCII, checked above, and ASCII is
        // a subset of UTF-8. `from_utf8` would only repeat the scan.
        Ok(Self(unsafe { core::str::from_utf8_unchecked(text) }))
    }
}

impl<'a> TryFrom<&'a str> for ImeiView<'a> {
    type Error = ImeiError;

    /// Validates that `text` is ASCII and wraps it without copying.
    ///
    /// # Errors
    ///
    /// Returns [`ImeiError`] with the byte index of the first non-ASCII
    /// character.
    fn try_from(text: &'a str) -> Result<Self, Self::Error> {
        Self::try_from(text.as_bytes())
    }
}

#[cfg(feature = "alloc")]
impl From<ImeiView<'_>> for Imei {
    fn from(view: ImeiView<'_>) -> Self {
        view.evaluate()
    }
}

impl fmt::Display for ImeiView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Debug for ImeiView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

impl Deref for ImeiView<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.0
    }
}

impl AsRef<str> for ImeiView<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl Borrow<str> for ImeiView<'_> {
    fn borrow(&self) -> &str {
        self.0
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for Imei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for Imei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[cfg(feature = "alloc")]
impl Deref for Imei {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for Imei {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl Borrow<str> for Imei {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// The error returned when IMEI text contains a non-ASCII byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImeiError {
    /// Zero-based index of the first non-ASCII byte.
    pub index: usize,
}

impl fmt::Display for ImeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "non-ASCII byte in IMEI text at index {}", self.index)
    }
}

impl core::error::Error for ImeiError {}

#[cfg(feature = "serde")]
impl serde::Serialize for ImeiView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

#[cfg(all(feature = "serde", feature = "alloc"))]
impl serde::Serialize for Imei {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[cfg(all(feature = "serde", feature = "alloc"))]
impl<'de> serde::Deserialize<'de> for Imei {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = alloc::string::String::deserialize(deserializer)?;
        ImeiView::try_from(text.as_str())
            .map(Self::from)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_accepts_any_ascii_length() {
        // Real IMEIs are 15 digits (the wiki handshake example declares
        // `0x000F`), but validation only requires ASCII.
        assert_eq!(ImeiView::try_from("").unwrap().as_str(), "");
        assert_eq!(ImeiView::try_from("12a").unwrap().as_str(), "12a");
    }

    #[test]
    fn view_rejects_the_first_non_ascii_byte() {
        assert_eq!(
            ImeiView::try_from(&b"12\x80\xff"[..]),
            Err(ImeiError { index: 2 })
        );
        assert_eq!(
            ImeiView::try_from("1234567890é"),
            Err(ImeiError { index: 10 })
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn evaluated_imei_keeps_the_text_and_order() {
        let view = ImeiView::try_from("356307042441013").unwrap();
        let imei = view.evaluate();
        assert_eq!(imei.as_str(), view.as_str());
        assert_eq!(Imei::from(view), imei);
    }
}
