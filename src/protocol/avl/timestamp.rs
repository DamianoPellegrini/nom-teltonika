use core::fmt;

/// An AVL record timestamp: milliseconds since the Unix epoch.
///
/// The integer is kept as sent, so the core doesn't pick a date-time
/// type. Convert it with [`From`], [`SystemTime`] (`std`), or `chrono`.
///
/// [`SystemTime`]: std::time::SystemTime
///
/// # Examples
///
/// ```
/// use nom_teltonika::protocol::AvlTimestamp;
///
/// let timestamp = AvlTimestamp::from(1_560_161_086_000);
/// assert_eq!(u64::from(timestamp), 1_560_161_086_000);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AvlTimestamp(u64);

impl From<u64> for AvlTimestamp {
    fn from(unix_millis: u64) -> Self {
        Self(unix_millis)
    }
}

impl From<AvlTimestamp> for u64 {
    fn from(timestamp: AvlTimestamp) -> Self {
        timestamp.0
    }
}

/// The error returned when a time can't be converted to or from an
/// [`AvlTimestamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampError {
    /// The time is before the Unix epoch.
    BeforeUnixEpoch,
    /// The time doesn't fit in the target type.
    OutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeUnixEpoch => f.write_str("time is before the Unix epoch"),
            Self::OutOfRange => f.write_str("time is out of range"),
        }
    }
}

impl core::error::Error for TimestampError {}

#[cfg(feature = "std")]
impl TryFrom<AvlTimestamp> for std::time::SystemTime {
    type Error = TimestampError;

    /// Converts the timestamp to a system time.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] if the platform's
    /// `SystemTime` can't represent it.
    fn try_from(timestamp: AvlTimestamp) -> Result<Self, Self::Error> {
        let elapsed = std::time::Duration::from_millis(timestamp.0);
        Self::UNIX_EPOCH
            .checked_add(elapsed)
            .ok_or(TimestampError::OutOfRange)
    }
}

#[cfg(feature = "std")]
impl TryFrom<std::time::SystemTime> for AvlTimestamp {
    type Error = TimestampError;

    /// Converts a system time, truncated to milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::BeforeUnixEpoch`] for times before the Unix
    /// epoch and [`TimestampError::OutOfRange`] when the milliseconds don't
    /// fit in a `u64`.
    fn try_from(time: std::time::SystemTime) -> Result<Self, Self::Error> {
        let elapsed = time
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| TimestampError::BeforeUnixEpoch)?;
        let millis = elapsed
            .as_millis()
            .try_into()
            .map_err(|_| TimestampError::OutOfRange)?;
        Ok(Self(millis))
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<AvlTimestamp> for chrono::DateTime<chrono::Utc> {
    type Error = TimestampError;

    /// Converts the timestamp to a UTC date and time.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] if `chrono` can't represent it.
    fn try_from(timestamp: AvlTimestamp) -> Result<Self, Self::Error> {
        use chrono::TimeZone;

        let millis = i64::try_from(timestamp.0).map_err(|_| TimestampError::OutOfRange)?;
        chrono::Utc
            .timestamp_millis_opt(millis)
            .single()
            .ok_or(TimestampError::OutOfRange)
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<chrono::DateTime<chrono::Utc>> for AvlTimestamp {
    type Error = TimestampError;

    /// Converts a UTC date and time, truncated to milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::BeforeUnixEpoch`] for times before the Unix
    /// epoch.
    fn try_from(time: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        let millis =
            u64::try_from(time.timestamp_millis()).map_err(|_| TimestampError::BeforeUnixEpoch)?;
        Ok(Self(millis))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    #[test]
    fn converts_to_and_from_system_time() {
        use std::time::{Duration, SystemTime};

        use super::*;

        let time = SystemTime::UNIX_EPOCH + Duration::from_millis(1_560_161_086_000);
        let timestamp = AvlTimestamp::try_from(time).unwrap();
        assert_eq!(u64::from(timestamp), 1_560_161_086_000);
        assert_eq!(SystemTime::try_from(timestamp), Ok(time));

        // A timestamp counts milliseconds: anything finer is dropped.
        let finer = SystemTime::UNIX_EPOCH + Duration::from_micros(1_234_567);
        assert_eq!(AvlTimestamp::try_from(finer).map(u64::from), Ok(1_234));

        let before = SystemTime::UNIX_EPOCH - Duration::from_millis(1);
        assert_eq!(
            AvlTimestamp::try_from(before),
            Err(TimestampError::BeforeUnixEpoch)
        );
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn converts_to_and_from_chrono() {
        use super::*;

        let timestamp = AvlTimestamp::from(1_560_161_086_000);
        let time = chrono::DateTime::<chrono::Utc>::try_from(timestamp).unwrap();
        assert_eq!(AvlTimestamp::try_from(time), Ok(timestamp));

        let before = chrono::TimeZone::timestamp_millis_opt(&chrono::Utc, -1).unwrap();
        assert!(AvlTimestamp::try_from(before).is_err());

        assert_eq!(
            chrono::DateTime::<chrono::Utc>::try_from(AvlTimestamp::from(u64::MAX)),
            Err(TimestampError::OutOfRange)
        );
    }
}
