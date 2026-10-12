/// GPS data of an AVL record, as sent.
///
/// Values are kept exactly as received: the wiki documents records without a
/// valid fix as data, not as malformed packets. Check
/// [`is_position_valid`](Self::is_position_valid) before using the position.
///
/// Layout: <https://wiki.teltonika-gps.com/view/Codec>, section "Codec 8 > AVL
/// Data > GPS element" (accessed 2026-09-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GpsElement {
    /// Longitude in degrees multiplied by 10,000,000; negative is west.
    pub longitude_raw: i32,
    /// Latitude in degrees multiplied by 10,000,000; negative is south.
    pub latitude_raw: i32,
    /// Altitude above sea level, in meters, read as unsigned.
    ///
    /// The wiki doesn't say how a device sends an altitude below sea level:
    /// see [`altitude_meters_signed`](Self::altitude_meters_signed).
    pub altitude_meters: u16,
    /// Heading, in degrees clockwise from north.
    pub angle_degrees: u16,
    /// Number of visible satellites; zero when there is no valid fix.
    pub satellites: u8,
    /// Speed calculated from satellites, in km/h.
    pub speed_kph: u16,
}

/// Precision factor of the coordinates ("Codec 8 > AVL Data > GPS element").
const COORDINATE_SCALE: f64 = 10_000_000.0;

impl GpsElement {
    /// Number of bytes of the GPS element in a record: longitude and
    /// latitude (4 each), altitude and angle (2 each), satellites (1), and
    /// speed (2).
    pub(crate) const LEN: usize = 15;

    /// Reads the GPS element of a record, every integer big-endian.
    pub(crate) const fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        let [
            x0,
            x1,
            x2,
            x3,
            y0,
            y1,
            y2,
            y3,
            h0,
            h1,
            a0,
            a1,
            satellites,
            s0,
            s1,
        ] = *bytes;
        Self {
            longitude_raw: i32::from_be_bytes([x0, x1, x2, x3]),
            latitude_raw: i32::from_be_bytes([y0, y1, y2, y3]),
            altitude_meters: u16::from_be_bytes([h0, h1]),
            angle_degrees: u16::from_be_bytes([a0, a1]),
            satellites,
            speed_kph: u16::from_be_bytes([s0, s1]),
        }
    }

    /// Writes the GPS element as a record carries it.
    pub(crate) const fn to_bytes(self) -> [u8; Self::LEN] {
        let [x0, x1, x2, x3] = self.longitude_raw.to_be_bytes();
        let [y0, y1, y2, y3] = self.latitude_raw.to_be_bytes();
        let [h0, h1] = self.altitude_meters.to_be_bytes();
        let [a0, a1] = self.angle_degrees.to_be_bytes();
        let [s0, s1] = self.speed_kph.to_be_bytes();
        [
            x0,
            x1,
            x2,
            x3,
            y0,
            y1,
            y2,
            y3,
            h0,
            h1,
            a0,
            a1,
            self.satellites,
            s0,
            s1,
        ]
    }

    /// Returns the longitude in degrees.
    ///
    /// Use [`longitude_raw`](Self::longitude_raw) when exact values matter.
    pub fn longitude_degrees(&self) -> f64 {
        f64::from(self.longitude_raw) / COORDINATE_SCALE
    }

    /// Returns the latitude in degrees.
    ///
    /// Use [`latitude_raw`](Self::latitude_raw) when exact values matter.
    pub fn latitude_degrees(&self) -> f64 {
        f64::from(self.latitude_raw) / COORDINATE_SCALE
    }

    /// Returns the altitude in meters, read as a signed number: negative
    /// below sea level.
    ///
    /// The wiki describes the field as "meters above sea level", in 2 bytes,
    /// and says nothing of its sign. It describes the sign of the
    /// coordinates only. So [`altitude_meters`](Self::altitude_meters) keeps
    /// the plain reading, where the bytes `FF F6` are 65,526 meters. Read as
    /// two's complement, like the coordinates, they are 10 meters below sea
    /// level, which exists on land: parts of the Netherlands, the Dead Sea
    /// shore.
    ///
    /// Nothing in the wiki settles which one a device means. Two facts
    /// favor the signed reading. Teltonika writes an altitude with a sign in
    /// another place: the IO element "ISO6709 Coordinates" (AVL ID 387) has
    /// the format `±DDMMSS.SSSS±DDDMMSS.SSSS±AAA.AAA/` ([FMB120 Teltonika
    /// Data Sending Parameters ID], accessed 2026-10-12). And most other
    /// decoders, [Traccar] among them, read these 2 bytes as signed. The
    /// two readings agree up to 32,767 meters, far above any road.
    ///
    /// Use this method unless you know that your devices send an unsigned
    /// altitude. To encode an altitude below sea level, set the field with
    /// [`i16::cast_unsigned`].
    ///
    /// Field: <https://wiki.teltonika-gps.com/view/Codec>, section "Codec 8 >
    /// AVL Data > GPS element" (accessed 2026-10-12).
    ///
    /// [FMB120 Teltonika Data Sending Parameters ID]: https://wiki.teltonika-gps.com/view/FMB120_Teltonika_Data_Sending_Parameters_ID
    /// [Traccar]: https://www.traccar.org
    ///
    /// # Examples
    ///
    /// ```
    /// use nom_teltonika::protocol::GpsElement;
    ///
    /// let gps = GpsElement {
    ///     longitude_raw: 47_000_000,
    ///     latitude_raw: 520_000_000,
    ///     altitude_meters: 0xfff6,
    ///     angle_degrees: 0,
    ///     satellites: 9,
    ///     speed_kph: 0,
    /// };
    /// assert_eq!(gps.altitude_meters, 65_526);
    /// assert_eq!(gps.altitude_meters_signed(), -10);
    /// ```
    pub const fn altitude_meters_signed(&self) -> i16 {
        self.altitude_meters.cast_signed()
    }

    /// Returns `true` if the record carries a valid fix.
    ///
    /// Without a fix, the wiki says satellites, angle, and speed are 0, while
    /// the coordinates repeat the last valid fix. This also checks that the
    /// coordinates are within ±180° and ±90°.
    ///
    /// # Examples
    ///
    /// ```
    /// use nom_teltonika::protocol::GpsElement;
    ///
    /// let mut gps = GpsElement {
    ///     longitude_raw: 254_732_167,
    ///     latitude_raw: 546_991_882,
    ///     altitude_meters: 0,
    ///     angle_degrees: 0,
    ///     satellites: 0,
    ///     speed_kph: 0,
    /// };
    /// assert!(!gps.is_position_valid());
    /// gps.satellites = 9;
    /// assert!(gps.is_position_valid());
    /// ```
    pub fn is_position_valid(&self) -> bool {
        self.satellites > 0
            && self.longitude_raw.unsigned_abs() <= 1_800_000_000
            && self.latitude_raw.unsigned_abs() <= 900_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_signed_big_endian_coordinates() {
        let sent = [
            0xf0, 0xd8, 0x5b, 0x60, // longitude
            0x20, 0x9a, 0x69, 0x0a, // latitude
            0x00, 0x7b, // altitude
            0x01, 0x2c, // angle
            0x09, // satellites
            0x00, 0x2a, // speed
        ];
        let gps = GpsElement::from_bytes(&sent);

        assert_eq!(gps.longitude_raw, -254_256_288);
        assert_eq!(gps.latitude_raw, 546_990_346);
        assert_eq!(gps.altitude_meters, 123);
        assert_eq!(gps.angle_degrees, 300);
        assert_eq!(gps.satellites, 9);
        assert_eq!(gps.speed_kph, 42);
        assert!(gps.longitude_degrees() < 0.0);
        assert_eq!(gps.to_bytes(), sent);
    }

    #[test]
    fn reads_altitude_unsigned_and_signed() {
        let mut sent = [0; GpsElement::LEN];
        sent[8..10].copy_from_slice(&[0xff, 0xf6]);
        let below = GpsElement::from_bytes(&sent);
        assert_eq!(below.altitude_meters, 65_526);
        assert_eq!(below.altitude_meters_signed(), -10);
        assert_eq!(below.to_bytes(), sent);

        sent[8..10].copy_from_slice(&[0x7f, 0xff]);
        let above = GpsElement::from_bytes(&sent);
        assert_eq!(above.altitude_meters, 32_767);
        assert_eq!(above.altitude_meters_signed(), 32_767);
    }
}
