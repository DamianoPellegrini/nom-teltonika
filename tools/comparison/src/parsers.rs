use std::hint::black_box;

use nom_teltonika::decoder::take_frame;
use nom_teltonika::protocol::{Frame, FrameView, IoValue, IoValueView};
use nom_teltonika_0_1_6::{AVLEventIOValue, TeltonikaFrame};
use teltonika_avl_protocol::codec8::Codec8Packet;

use crate::Corpus;

/// The counts and the checksum a parser returns for a corpus.
///
/// The checksum is the wrapping sum of these values:
///
/// - For each record, the timestamp in milliseconds, altitude, angle,
///   satellites, speed, and event IO ID.
/// - For each IO element, the ID and the value. A variable-length value
///   counts as the sum of its bytes.
/// - For each Codec 12 message, the payload length.
///
/// Coordinates and priorities are not summed, because the parsers return
/// them in different types.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    /// Frames decoded.
    pub frames: u64,
    /// AVL records in the frames.
    pub records: u64,
    /// IO elements in the records.
    pub io_elements: u64,
    /// The sum of the values read.
    pub checksum: u64,
}

impl Totals {
    fn add(&mut self, value: u64) {
        self.checksum = self.checksum.wrapping_add(value);
    }

    fn record(
        &mut self,
        millis: u64,
        altitude: u16,
        angle: u16,
        satellites: u8,
        speed: u16,
        event_io_id: u16,
    ) {
        self.records += 1;
        self.add(millis);
        self.add(altitude.into());
        self.add(angle.into());
        self.add(satellites.into());
        self.add(speed.into());
        self.add(event_io_id.into());
    }

    fn io_element(&mut self, id: u16, value: u64) {
        self.io_elements += 1;
        self.add(id.into());
        self.add(value);
    }

    fn message(&mut self, payload_len: usize) {
        self.add(payload_len as u64);
    }
}

/// Returns the sum of `bytes`.
fn sum(bytes: &[u8]) -> u64 {
    bytes.iter().map(|byte| u64::from(*byte)).sum()
}

/// A parser to benchmark.
///
/// A crate has one entry for each way of using it.
#[derive(Debug, Clone, Copy)]
pub struct Parser {
    /// A short name, for benchmark IDs.
    pub id: &'static str,
    /// The crate and its version, for the report.
    pub name: &'static str,
    /// What decoding returns, for the report.
    pub output: &'static str,
    /// Whether the parser decodes Codec 8 only.
    pub codec8_only: bool,
    /// Whether [`decode`](Self::decode) reads every value.
    ///
    /// If `false`, it only counts frames and records.
    pub reads_values: bool,
    /// Decodes consecutive frames and returns their totals.
    ///
    /// # Panics
    ///
    /// Panics if the parser returns an error.
    pub decode: fn(&[u8]) -> Totals,
}

impl Parser {
    /// Returns whether the parser can decode every frame of `corpus`.
    pub fn decodes(&self, corpus: &Corpus) -> bool {
        corpus.codec8_only || !self.codec8_only
    }
}

/// The benchmark ID of the parser the report compares the others to.
pub const BASELINE_ID: &str = "nom_teltonika_0_1_6";

/// The parsers to benchmark, in the order of the report.
pub const PARSERS: [Parser; 6] = [
    Parser {
        id: "nom_teltonika_validated",
        name: "nom-teltonika",
        output: "Views, records counted",
        codec8_only: false,
        reads_values: false,
        decode: current_validated,
    },
    Parser {
        id: "nom_teltonika_views",
        name: "nom-teltonika",
        output: "Views, every value read",
        codec8_only: false,
        reads_values: true,
        decode: current_views,
    },
    Parser {
        id: "nom_teltonika_owned",
        name: "nom-teltonika",
        output: "Owned",
        codec8_only: false,
        reads_values: true,
        decode: current_owned,
    },
    Parser {
        id: BASELINE_ID,
        name: "nom-teltonika 0.1.6",
        output: "Owned",
        codec8_only: false,
        reads_values: true,
        decode: nom_teltonika_0_1_6,
    },
    Parser {
        id: "teltonika_rs_0_1_1",
        name: "teltonika-rs 0.1.1",
        output: "Owned",
        codec8_only: true,
        reads_values: true,
        decode: teltonika_rs,
    },
    Parser {
        id: "teltonika_avl_protocol_0_1_0",
        name: "teltonika-avl-protocol 0.1.0",
        output: "Fixed capacity",
        codec8_only: true,
        reads_values: true,
        decode: teltonika_avl_protocol,
    },
];

/// Validates each frame and counts its records, without reading values.
fn current_validated(mut input: &[u8]) -> Totals {
    let mut totals = Totals::default();
    while !input.is_empty() {
        totals.frames += 1;
        if let FrameView::Avl(packet) = take_frame(&mut input).expect("a valid frame") {
            totals.records += packet.records().len() as u64;
        }
    }
    totals
}

fn current_views(mut input: &[u8]) -> Totals {
    let mut totals = Totals::default();
    while !input.is_empty() {
        totals.frames += 1;
        match take_frame(&mut input).expect("a valid frame") {
            FrameView::Avl(packet) => {
                for record in packet.records() {
                    let gps = record.gps();
                    // The other parsers always convert the coordinates.
                    black_box((gps.longitude_raw, gps.latitude_raw));
                    totals.record(
                        record.timestamp().into(),
                        gps.altitude_meters,
                        gps.angle_degrees,
                        gps.satellites,
                        gps.speed_kph,
                        record.event_io_id().map_or(0, u16::from),
                    );
                    for element in record.io_elements() {
                        let value = match element.value() {
                            IoValueView::U8(value) => value.into(),
                            IoValueView::U16(value) => value.into(),
                            IoValueView::U32(value) => value.into(),
                            IoValueView::U64(value) => value,
                            IoValueView::Bytes(bytes) => sum(bytes),
                        };
                        totals.io_element(element.id().into(), value);
                    }
                }
            }
            FrameView::Gprs(packet) => {
                for message in packet.messages() {
                    totals.message(message.payload().len());
                }
            }
            _ => unreachable!("an AVL or a GPRS frame"),
        }
    }
    totals
}

fn current_owned(mut input: &[u8]) -> Totals {
    let mut totals = Totals::default();
    while !input.is_empty() {
        totals.frames += 1;
        match take_frame(&mut input).expect("a valid frame").evaluate() {
            Frame::Avl(packet) => {
                for record in packet.records() {
                    let gps = record.gps();
                    totals.record(
                        record.timestamp().into(),
                        gps.altitude_meters,
                        gps.angle_degrees,
                        gps.satellites,
                        gps.speed_kph,
                        record.event_io_id().map_or(0, u16::from),
                    );
                    for element in record.io_elements() {
                        let value = match element.value() {
                            IoValue::U8(value) => (*value).into(),
                            IoValue::U16(value) => (*value).into(),
                            IoValue::U32(value) => (*value).into(),
                            IoValue::U64(value) => *value,
                            IoValue::Bytes(bytes) => sum(bytes),
                        };
                        totals.io_element(element.id().into(), value);
                    }
                }
            }
            Frame::Gprs(packet) => {
                for message in packet.messages() {
                    totals.message(message.payload().len());
                }
            }
            _ => unreachable!("an AVL or a GPRS frame"),
        }
    }
    totals
}

fn nom_teltonika_0_1_6(mut input: &[u8]) -> Totals {
    let mut totals = Totals::default();
    while !input.is_empty() {
        totals.frames += 1;
        let (rest, frame) = nom_teltonika_0_1_6::parser::tcp_frame(input).expect("a valid frame");
        input = rest;
        match frame {
            TeltonikaFrame::AVL(frame) => {
                for record in &frame.records {
                    totals.record(
                        record.timestamp.timestamp_millis() as u64,
                        record.altitude,
                        record.angle,
                        record.satellites,
                        record.speed,
                        record.trigger_event_id,
                    );
                    for element in &record.io_events {
                        let value = match &element.value {
                            AVLEventIOValue::U8(value) => (*value).into(),
                            AVLEventIOValue::U16(value) => (*value).into(),
                            AVLEventIOValue::U32(value) => (*value).into(),
                            AVLEventIOValue::U64(value) => *value,
                            AVLEventIOValue::Variable(bytes) => sum(bytes),
                        };
                        totals.io_element(element.id, value);
                    }
                }
            }
            TeltonikaFrame::GPRS(frame) => {
                for response in &frame.command_responses {
                    totals.message(response.len());
                }
            }
        }
    }
    totals
}

fn teltonika_rs(mut input: &[u8]) -> Totals {
    let mut totals = Totals::default();
    while !input.is_empty() {
        totals.frames += 1;
        let (rest, frame) =
            teltonika_rs::parser::parse_teltonika_codec_8(input).expect("a valid frame");
        input = rest;
        for record in &frame.avl_data {
            totals.record(
                record.timestamp,
                record.gps.altitude,
                record.gps.angle,
                record.gps.visible_satellites,
                record.gps.speed,
                record.io.event_io_id.into(),
            );
            let groups = [
                &record.io.io_1_byte_elements,
                &record.io.io_2_byte_elements,
                &record.io.io_4_byte_elements,
                &record.io.io_8_byte_elements,
            ];
            for element in groups.into_iter().flatten().flatten() {
                totals.io_element(element.id.into(), element.value);
            }
        }
    }
    totals
}

fn teltonika_avl_protocol(mut input: &[u8]) -> Totals {
    let mut totals = Totals::default();
    while !input.is_empty() {
        totals.frames += 1;
        let (len, packet) = Codec8Packet::decode(input).expect("a valid frame");
        input = &input[len..];
        for record in &packet.avl_data_records {
            let gps = &record.gps_element;
            totals.record(
                record.timestamp,
                gps.altitude as u16,
                gps.angle,
                gps.satellites,
                gps.speed,
                record.event_io_id.into(),
            );
            for element in &record.n1_elements {
                totals.io_element(element.id.into(), element.value.into());
            }
            for element in &record.n2_elements {
                totals.io_element(element.id.into(), element.value.into());
            }
            for element in &record.n4_elements {
                totals.io_element(element.id.into(), element.value.into());
            }
            for element in &record.n8_elements {
                totals.io_element(element.id.into(), element.value);
            }
        }
    }
    totals
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Enough for thousands of frames of every kind.
    const LEN: usize = 1024 * 1024;

    #[test]
    fn parsers_find_the_same_values() {
        for corpus in [Corpus::codec8(LEN), Corpus::mixed(LEN)] {
            let mut expected = None;
            for parser in PARSERS.iter().filter(|parser| parser.decodes(&corpus)) {
                let totals = (parser.decode)(&corpus.bytes);
                assert_eq!(totals.frames, corpus.frames, "{}", parser.id);
                assert_eq!(totals.records, corpus.records, "{}", parser.id);
                if parser.reads_values {
                    assert!(totals.io_elements > 0, "{}", parser.id);
                    assert_eq!(*expected.get_or_insert(totals), totals, "{}", parser.id);
                }
            }
        }
    }

    #[test]
    fn every_parser_decodes_the_codec8_corpus() {
        let corpus = Corpus::codec8(LEN);
        assert!(PARSERS.iter().all(|parser| parser.decodes(&corpus)));
    }

    #[test]
    fn the_baseline_is_a_parser_of_every_corpus() {
        let baseline = PARSERS.iter().find(|parser| parser.id == BASELINE_ID);
        assert!(baseline.is_some_and(|parser| !parser.codec8_only));
    }
}
