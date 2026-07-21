use std::time::{Duration, UNIX_EPOCH};

use nom_teltonika::protocol::{AvlTimestamp, TimestampError};

#[test]
fn should_round_trip_system_time_at_millisecond_precision() {
    let system_time = UNIX_EPOCH + Duration::from_micros(1_234_567);

    let timestamp = AvlTimestamp::from_system_time(system_time).unwrap();

    assert_eq!(timestamp.unix_millis(), 1_234);
    assert_eq!(
        timestamp.to_system_time(),
        Ok(UNIX_EPOCH + Duration::from_millis(1_234))
    );
}

#[test]
fn should_reject_system_time_before_unix_epoch() {
    let system_time = UNIX_EPOCH - Duration::from_millis(1);

    assert!(matches!(
        AvlTimestamp::from_system_time(system_time),
        Err(TimestampError::BeforeUnixEpoch)
    ));
}

#[cfg(feature = "chrono")]
#[test]
fn should_round_trip_chrono_timestamp() {
    use chrono::{TimeZone, Utc};

    let datetime = Utc.timestamp_millis_opt(1_546_301_234_567).unwrap();

    let timestamp = AvlTimestamp::try_from(datetime).unwrap();
    let converted = chrono::DateTime::<Utc>::try_from(timestamp).unwrap();

    assert_eq!(timestamp.unix_millis(), 1_546_301_234_567);
    assert_eq!(converted, datetime);
}

#[cfg(feature = "chrono")]
#[test]
fn should_reject_chrono_values_outside_wire_range() {
    use chrono::{TimeZone, Utc};

    let before_epoch = Utc.timestamp_millis_opt(-1).unwrap();

    assert!(AvlTimestamp::try_from(before_epoch).is_err());
    assert!(chrono::DateTime::<Utc>::try_from(AvlTimestamp::from_unix_millis(u64::MAX)).is_err());
}
