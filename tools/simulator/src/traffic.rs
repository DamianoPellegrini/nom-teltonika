use std::collections::VecDeque;

use nom_teltonika::encoder::{
    AvlRecordFields, DatagramHeaderFields, EncodeAvlError, encode_avl_datagram, encode_avl_frame,
};
use nom_teltonika::protocol::{
    AvlCodec, AvlTimestamp, GenerationType, GpsElement, ImeiView, IoId, Priority,
};

// The records follow what FMB devices send, as seen in captures of an FMB003
// and an FM3001: the same IO elements, widths, and value ranges. IO IDs mean
// what they mean on FMB devices ("FMB Teltonika Data Sending Parameters
// ID"); other models may differ.
const IGNITION: u16 = 239;
const MOVEMENT: u16 = 240;
const DATA_MODE: u16 = 80;
const GSM_SIGNAL: u16 = 21;
const SLEEP_MODE: u16 = 200;
const GNSS_STATUS: u16 = 69;
const PDOP: u16 = 181;
const HDOP: u16 = 182;
const EXTERNAL_VOLTAGE: u16 = 66;
const SPEED: u16 = 24;
const CELL_ID: u16 = 205;
const AREA_CODE: u16 = 206;
const BATTERY_VOLTAGE: u16 = 67;
const BATTERY_CURRENT: u16 = 68;
const AXIS_X: u16 = 17;
const AXIS_Y: u16 = 18;
const AXIS_Z: u16 = 19;
const OPERATOR: u16 = 241;
const TRIP_ODOMETER: u16 = 199;
const TOTAL_ODOMETER: u16 = 16;
const ICCID_1: u16 = 11;
const ICCID_2: u16 = 14;
/// The vehicle identification number: 17 ASCII characters, sent in Codec 8
/// Extended as the FM3001 does.
const VIN: u16 = 256;

/// Characters of a VIN: digits and capital letters but I, O, and Q.
const VIN_CHARACTERS: &[u8] = b"0123456789ABCDEFGHJKLMNPRSTUVWXYZ";

/// Deterministic AVL traffic from one simulated vehicle.
///
/// The vehicle alternates trips and stops. On a trip its speed and heading
/// change smoothly; stopped, it stands still with the ignition off. A record
/// is taken every record period; the ignition turning on or off adds an
/// eventual record, as FMB devices do. Records carry the IO elements an
/// FMB003 sends, plus the VIN in Codec 8 Extended.
///
/// A packet holds up to `records_per_packet` records, fewer when they don't
/// fit in a frame of the codec (1280 bytes for Codec 8 and Codec 8
/// Extended); the rest go in the next packet. The same
/// settings and seed always produce the same bytes.
#[derive(Debug, Clone)]
pub struct Traffic {
    codec: AvlCodec,
    records_per_packet: u8,
    record_period_millis: u64,
    rng: fastrand::Rng,
    clock_millis: u64,
    vehicle: Vehicle,
    /// Records taken but not yet in a packet.
    queue: VecDeque<RecordValues>,
}

/// A packet ready to send, and the number of records in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The frame or datagram bytes.
    pub bytes: Vec<u8>,
    /// Records in the packet: the count the server acknowledges.
    pub records: u8,
}

/// What the vehicle is doing and what its device measures.
#[derive(Debug, Clone)]
pub(crate) struct Vehicle {
    pub(crate) longitude: f64,
    pub(crate) latitude: f64,
    pub(crate) altitude: f64,
    pub(crate) heading: f64,
    pub(crate) speed_kph: f64,
    pub(crate) ignition: bool,
    pub(crate) satellites: u8,
    /// Records left before the ignition changes.
    phase_left: u32,
    odometer_meters: f64,
    trip_meters: f64,
    pub(crate) operator: u32,
    pub(crate) area_code: u16,
    pub(crate) cell_id: u16,
    pub(crate) gsm_signal: u8,
    iccid: (u64, u64),
    vin: [u8; 17],
}

/// One record's values, owned, so [`AvlRecordFields`] can borrow them.
#[derive(Debug, Clone)]
struct RecordValues {
    timestamp: AvlTimestamp,
    priority: Priority,
    event: Option<IoId>,
    gps: GpsElement,
    io_u8: [(IoId, u8); 6],
    io_u16: [(IoId, u16); 11],
    io_u32: [(IoId, u32); 3],
    io_u64: [(IoId, u64); 2],
}

impl Traffic {
    /// Creates the traffic of one vehicle.
    ///
    /// The first record is taken at `start_millis` (milliseconds since the
    /// Unix epoch), the next ones every `record_period_millis`.
    ///
    /// # Panics
    ///
    /// Panics if `records_per_packet` is 0.
    pub fn new(
        codec: AvlCodec,
        records_per_packet: u8,
        record_period_millis: u64,
        seed: u64,
        start_millis: u64,
    ) -> Self {
        assert!(records_per_packet > 0, "a packet holds at least one record");
        let mut rng = fastrand::Rng::with_seed(seed);
        let vehicle = Vehicle::new(&mut rng);
        Self {
            codec,
            records_per_packet,
            record_period_millis,
            rng,
            clock_millis: start_millis,
            vehicle,
            queue: VecDeque::new(),
        }
    }

    /// Returns the time of the next record, in milliseconds since the Unix
    /// epoch.
    pub fn clock_millis(&self) -> u64 {
        self.clock_millis
    }

    /// Returns the records taken but not yet in a packet.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Returns the vehicle's current state.
    pub(crate) fn vehicle(&self) -> &Vehicle {
        &self.vehicle
    }

    /// Returns the next packet as a TCP frame.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeAvlError`] if a single record doesn't fit in a frame,
    /// which the simulator's records never cause.
    pub fn next_frame(&mut self) -> Result<Packet, EncodeAvlError> {
        self.next_packet(encode_avl_frame)
    }

    /// Returns the next packet as a UDP datagram with the given IDs and
    /// IMEI.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeAvlError`] if a single record doesn't fit in a frame,
    /// which the simulator's records never cause.
    pub fn next_datagram(
        &mut self,
        packet_id: u16,
        avl_packet_id: u8,
        imei: ImeiView<'_>,
    ) -> Result<Packet, EncodeAvlError> {
        self.next_packet(|codec, records| {
            // A datagram carries the same AVL data as a frame: keep it
            // within the frame limit of its codec.
            encode_avl_frame(codec, records)?;
            let header = DatagramHeaderFields {
                packet_id,
                avl_packet_id,
                imei,
            };
            encode_avl_datagram(header, codec, records)
        })
    }

    /// Takes records until a packet is full, then encodes as many as fit.
    fn next_packet(
        &mut self,
        encode: impl Fn(AvlCodec, &[AvlRecordFields<'_>]) -> Result<Vec<u8>, EncodeAvlError>,
    ) -> Result<Packet, EncodeAvlError> {
        while self.queue.len() < usize::from(self.records_per_packet) {
            self.take_record();
        }
        let vin = [(IoId::from(VIN), &self.vehicle.vin[..])];
        let mut count = usize::from(self.records_per_packet);
        loop {
            let records: Vec<_> = self
                .queue
                .iter()
                .take(count)
                .map(|values| fields(self.codec, values, &vin))
                .collect();
            match encode(self.codec, &records) {
                Ok(bytes) => {
                    drop(records);
                    self.queue.drain(..count);
                    let records = u8::try_from(count).expect("at most `records_per_packet`");
                    return Ok(Packet { bytes, records });
                }
                Err(EncodeAvlError::TooLong { .. }) if count > 1 => count -= 1,
                Err(error) => return Err(error),
            }
        }
    }

    /// Advances the vehicle by one record period and queues its record,
    /// after an eventual record if the ignition changed.
    fn take_record(&mut self) {
        let seconds = self.record_period_millis as f64 / 1000.0;
        if self.vehicle.step(seconds, &mut self.rng) {
            let record = self.record(Some(IoId::from(IGNITION)), Priority::High);
            self.queue.push_back(record);
        }
        let record = self.record(None, Priority::Low);
        self.queue.push_back(record);
        self.clock_millis += self.record_period_millis;
    }

    fn record(&mut self, event: Option<IoId>, priority: Priority) -> RecordValues {
        let rng = &mut self.rng;
        let vehicle = &self.vehicle;
        let moving = vehicle.speed_kph >= 1.0;
        let speed = vehicle.speed_kph.round() as u16;
        let external_millivolts = if vehicle.ignition {
            rng.u16(13_900..=14_300)
        } else {
            rng.u16(12_300..=12_600)
        };
        // Accelerometer axes in mg, signed, sent as two's complement: the
        // device lies flat, so Z holds gravity.
        let vibration = if moving { 60 } else { 8 };
        let mut axis = |center: i16| (center + rng.i16(-vibration..=vibration)) as u16;
        let (axis_x, axis_y, axis_z) = (axis(0), axis(0), axis(-1000));
        RecordValues {
            timestamp: AvlTimestamp::from(self.clock_millis),
            priority,
            event,
            gps: GpsElement {
                longitude_raw: (vehicle.longitude * 1e7).round() as i32,
                latitude_raw: (vehicle.latitude * 1e7).round() as i32,
                altitude_meters: vehicle.altitude.round() as u16,
                angle_degrees: vehicle.heading.round() as u16 % 360,
                satellites: vehicle.satellites,
                speed_kph: speed,
            },
            io_u8: [
                (IoId::from(IGNITION), u8::from(vehicle.ignition)),
                (IoId::from(MOVEMENT), u8::from(moving)),
                // 0: home network, stopped; 1: home network, moving.
                (IoId::from(DATA_MODE), u8::from(moving)),
                (IoId::from(GSM_SIGNAL), vehicle.gsm_signal),
                (IoId::from(SLEEP_MODE), 0),
                // 1: GNSS on, with a fix.
                (IoId::from(GNSS_STATUS), 1),
            ],
            io_u16: [
                (IoId::from(PDOP), rng.u16(9..=16)),
                (IoId::from(HDOP), rng.u16(6..=11)),
                (IoId::from(EXTERNAL_VOLTAGE), external_millivolts),
                (IoId::from(SPEED), speed),
                (IoId::from(CELL_ID), vehicle.cell_id),
                (IoId::from(AREA_CODE), vehicle.area_code),
                (IoId::from(BATTERY_VOLTAGE), rng.u16(4_020..=4_110)),
                (IoId::from(BATTERY_CURRENT), 0),
                (IoId::from(AXIS_X), axis_x),
                (IoId::from(AXIS_Y), axis_y),
                (IoId::from(AXIS_Z), axis_z),
            ],
            io_u32: [
                (IoId::from(OPERATOR), vehicle.operator),
                (IoId::from(TRIP_ODOMETER), vehicle.trip_meters as u32),
                (IoId::from(TOTAL_ODOMETER), vehicle.odometer_meters as u32),
            ],
            io_u64: [
                (IoId::from(ICCID_1), vehicle.iccid.0),
                (IoId::from(ICCID_2), vehicle.iccid.1),
            ],
        }
    }
}

/// Returns the fields of `values` for `codec`; `vin` goes into every Codec
/// 8 Extended record.
fn fields<'a>(
    codec: AvlCodec,
    values: &'a RecordValues,
    vin: &'a [(IoId, &'a [u8])],
) -> AvlRecordFields<'a> {
    let mut record = AvlRecordFields::new(values.timestamp, values.priority, values.gps)
        .with_io_u8(&values.io_u8)
        .with_io_u16(&values.io_u16)
        .with_io_u32(&values.io_u32)
        .with_io_u64(&values.io_u64);
    if let Some(event) = values.event {
        record = record.with_event_io_id(event);
    }
    match codec {
        AvlCodec::Codec16 => {
            let generation_type = if values.event.is_some() {
                GenerationType::OnChange
            } else {
                GenerationType::Periodical
            };
            record = record.with_generation_type(generation_type);
        }
        AvlCodec::Codec8Extended => record = record.with_io_bytes(vin),
        _ => {}
    }
    record
}

impl Vehicle {
    fn new(rng: &mut fastrand::Rng) -> Self {
        Self {
            // Somewhere around Vilnius, where Teltonika is based.
            longitude: 25.20 + rng.f64() * 0.15,
            latitude: 54.63 + rng.f64() * 0.10,
            altitude: 100.0 + rng.f64() * 40.0,
            heading: f64::from(rng.u16(0..360)),
            speed_kph: 0.0,
            ignition: false,
            satellites: rng.u8(9..=15),
            phase_left: rng.u32(1..=5),
            odometer_meters: f64::from(rng.u32(10_000_000..=200_000_000)),
            trip_meters: 0.0,
            // MCC 246, MNC 02: a Lithuanian operator.
            operator: 24_602,
            area_code: rng.u16(1..=60_000),
            cell_id: rng.u16(1..=60_000),
            gsm_signal: rng.u8(3..=5),
            iccid: (
                rng.u64(8_937_000_000..=8_937_999_999),
                rng.u64(1_000_000_000..=9_999_999_999),
            ),
            vin: std::array::from_fn(|_| VIN_CHARACTERS[rng.usize(..VIN_CHARACTERS.len())]),
        }
    }

    /// Advances the vehicle by `seconds`; returns `true` if the ignition
    /// changed.
    fn step(&mut self, seconds: f64, rng: &mut fastrand::Rng) -> bool {
        let changed = self.phase_left == 0;
        if changed {
            self.ignition = !self.ignition;
            // Trips last longer than stops, in records.
            self.phase_left = if self.ignition {
                rng.u32(60..=600)
            } else {
                rng.u32(10..=120)
            };
            if self.ignition {
                self.trip_meters = 0.0;
            }
        }
        self.phase_left -= 1;

        if self.ignition {
            // At most 3 km/h per second either way, toward a cruising speed
            // between 30 and 110 km/h.
            let target = 30.0 + rng.f64() * 80.0;
            let change = ((target - self.speed_kph) * 0.1).clamp(-3.0, 3.0) * seconds;
            self.speed_kph = (self.speed_kph + change + rng.f64() - 0.5).clamp(0.0, 130.0);
            if self.speed_kph >= 1.0 {
                self.heading = (self.heading + (rng.f64() - 0.5) * 10.0).rem_euclid(360.0);
            }
        } else {
            self.speed_kph = 0.0;
        }

        let meters = self.speed_kph / 3.6 * seconds;
        let radians = self.heading.to_radians();
        self.latitude += meters * radians.cos() / 111_320.0;
        self.longitude += meters * radians.sin() / (111_320.0 * self.latitude.to_radians().cos());
        self.altitude = (self.altitude + rng.f64() - 0.5).clamp(60.0, 250.0);
        self.odometer_meters += meters;
        self.trip_meters += meters;
        if rng.u8(..20) == 0 {
            self.satellites = self
                .satellites
                .saturating_add_signed(rng.i8(-1..=1))
                .clamp(6, 18);
            self.gsm_signal = self
                .gsm_signal
                .saturating_add_signed(rng.i8(-1..=1))
                .clamp(2, 5);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use nom_teltonika::decoder::take_frame;
    use nom_teltonika::protocol::FrameView;

    use super::*;

    const START: u64 = 1_700_000_000_000;

    #[test]
    fn frames_decode_back_for_every_codec() {
        for codec in [
            AvlCodec::Codec8,
            AvlCodec::Codec8Extended,
            AvlCodec::Codec16,
        ] {
            let mut traffic = Traffic::new(codec, 5, 1_000, 7, START);
            for _ in 0..10 {
                let packet = traffic.next_frame().unwrap();
                let Ok(FrameView::Avl(avl)) = take_frame(&mut &packet.bytes[..]) else {
                    panic!("expected an AVL frame");
                };
                assert_eq!(avl.codec(), codec);
                assert_eq!(avl.records().len(), usize::from(packet.records));
            }
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_bytes() {
        let mut first = Traffic::new(AvlCodec::Codec8Extended, 3, 1_000, 42, START);
        let mut second = Traffic::new(AvlCodec::Codec8Extended, 3, 1_000, 42, START);
        for _ in 0..5 {
            assert_eq!(first.next_frame().unwrap(), second.next_frame().unwrap());
        }
    }

    #[test]
    fn records_that_dont_fit_go_in_the_next_packet() {
        let mut traffic = Traffic::new(AvlCodec::Codec8Extended, 20, 1_000, 1, START);
        let packet = traffic.next_frame().unwrap();
        assert!(packet.records < 20, "{} records", packet.records);
        assert!(packet.bytes.len() <= 1280);
        assert!(traffic.queued() > 0);
    }

    #[test]
    fn records_are_spaced_by_the_period_and_ignition_changes_are_events() {
        let mut traffic = Traffic::new(AvlCodec::Codec8, 10, 30_000, 3, START);
        let mut previous: Option<u64> = None;
        let mut events = 0;
        for _ in 0..50 {
            let packet = traffic.next_frame().unwrap();
            let Ok(FrameView::Avl(avl)) = take_frame(&mut &packet.bytes[..]) else {
                panic!("expected an AVL frame");
            };
            for record in avl.records() {
                let millis = u64::from(record.timestamp());
                match record.event_io_id() {
                    Some(event) => {
                        assert_eq!(u16::from(event), IGNITION);
                        events += 1;
                    }
                    None => {
                        if let Some(previous) = previous {
                            assert_eq!(millis - previous, 30_000);
                        }
                        previous = Some(millis);
                    }
                }
            }
        }
        assert!(events > 0, "no ignition change in 500 records");
    }
}
