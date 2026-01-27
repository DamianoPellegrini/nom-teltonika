use chrono::{TimeZone, Utc};
use nom::{
    bytes::streaming::{tag, take},
    character::streaming::anychar,
    combinator::{cond, verify},
    error::ParseError,
    multi::{length_count, length_data},
    number::streaming::{be_i32, be_u16, be_u32, be_u64, be_u8},
    IResult, Parser,
};

use crate::protocol::*;

/// Parse a response from a command
///
/// Takes the response from a command and returns the response message
pub fn command_response(input: &[u8]) -> IResult<&[u8], &[u8]> {
    // preamble
    let (remaining, _preamble) = tag([0; 4])(input)?;

    // data size
    let (remaining, data_size) = be_u32(remaining)?;

    // codec id
    let (remaining, _codec_id) = tag([0x0C])(remaining)?;

    // response quantity 1
    let (remaining, _) = take(1usize)(remaining)?;

    // type
    let (remaining, _codec_id) = tag([0x06])(remaining)?;

    // response size
    let (remaining, response_size) = be_u32(remaining)?;

    // response
    let (remaining, response) = take(response_size)(remaining)?;

    // response quantity 2
    let (remaining, _) = take(1usize)(remaining)?;

    // crc
    let calculated_crc16 = crate::crc16(&input[8..8 + data_size as usize]);
    let (remaining, _crc16) = verify(be_u32, |crc16| *crc16 == calculated_crc16 as u32)(remaining)?;

    Ok((remaining, response))
}

/// Parse an imei
///
/// Following the teltonika protocol, takes a `&[u8]`: [`u16`] as `length` and `length` bytes as [`String`]
pub fn imei(input: &[u8]) -> IResult<&[u8], String> {
    let (input, imei) = length_count(be_u16, anychar)(input)?;
    Ok((input, imei.iter().collect()))
}

fn codec(input: &[u8]) -> IResult<&[u8], Codec> {
    let (input, codec) = be_u8(input)?;
    Ok((input, codec.into()))
}

fn priority(input: &[u8]) -> IResult<&[u8], Priority> {
    let (input, priority) = be_u8(input)?;
    Ok((input, priority.into()))
}

fn event_generation_cause(input: &[u8]) -> IResult<&[u8], EventGenerationCause> {
    let (input, generation_type) = be_u8(input)?;
    Ok((input, generation_type.into()))
}

fn event_id<'a>(codec: Codec) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u16> {
    move |input| {
        let (input, event_id) = match codec {
            Codec::C8 => be_u8(input).map(|(i, v)| (i, v as u16)),
            Codec::C8Ext => be_u16(input),
            Codec::C16 => be_u16(input),
            _ => panic!("Unsupported codec: {:?}", codec),
        }?;
        Ok((input, event_id))
    }
}

fn event_count<'a>(codec: Codec) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u16> {
    move |input| {
        let (input, event_count) = match codec {
            Codec::C8 => be_u8(input).map(|(i, v)| (i, v as u16)),
            Codec::C8Ext => be_u16(input),
            Codec::C16 => be_u8(input).map(|(i, v)| (i, v as u16)),
            _ => panic!("Unsupported codec: {:?}", codec),
        }?;
        Ok((input, event_count))
    }
}

fn event<'a, O, E, F>(
    codec: Codec,
    mut f: F,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], (u16, O), E>
where
    E: ParseError<&'a [u8]>,
    F: Parser<&'a [u8], O, E>,
    nom::Err<E>: From<nom::Err<nom::error::Error<&'a [u8]>>>,
{
    move |input| {
        let (input, id) = event_id(codec)(input)?;
        let (input, value) = f.parse(input)?;
        Ok((input, (id, value)))
    }
}

fn io_events<'a>(
    codec: Codec,
) -> impl Parser<&'a [u8], Vec<AVLEventIO>, nom::error::Error<&'a [u8]>> {
    move |input| {
        let (input, u8_ios) = length_count(
            event_count(codec),
            event(codec, be_u8).map(|(id, val)| AVLEventIO {
                id,
                value: AVLEventIOValue::U8(val),
            }),
        )(input)?;

        let (input, u16_ios) = length_count(
            event_count(codec),
            event(codec, be_u16).map(|(id, val)| AVLEventIO {
                id,
                value: AVLEventIOValue::U16(val),
            }),
        )(input)?;

        let (input, u32_ios) = length_count(
            event_count(codec),
            event(codec, be_u32).map(|(id, val)| AVLEventIO {
                id,
                value: AVLEventIOValue::U32(val),
            }),
        )(input)?;

        let (input, u64_ios) = length_count(
            event_count(codec),
            event(codec, be_u64).map(|(id, val)| AVLEventIO {
                id,
                value: AVLEventIOValue::U64(val),
            }),
        )(input)?;

        let (input, xb_ios) = cond(
            codec == Codec::C8Ext,
            length_count(
                event_count(codec),
                event(codec, length_count(event_count(codec), be_u8)).map(|(id, val)| {
                    let value = match id {
                        385 => match parse_beacon_data_385(&val) {
                            Ok((_, beacon_data)) => AVLEventIOValue::Beacon(beacon_data),
                            Err(_) => AVLEventIOValue::Variable(val),
                        },
                        548 => match parse_beacon_data_548(&val) {
                            Ok((_, beacon_data)) => AVLEventIOValue::Beacon(beacon_data),
                            Err(e) => AVLEventIOValue::Variable(val),
                        },
                        10828 | 10829 | 10831 => match parse_beacon_data(&val) {
                            Ok((_, beacon_data)) => AVLEventIOValue::Beacon(beacon_data),
                            Err(_) => AVLEventIOValue::Variable(val),
                        },
                        _ => AVLEventIOValue::Variable(val),
                    };
                    AVLEventIO { id, value }
                }),
            ),
        )(input)?;

        let mut io_events = vec![];
        io_events.extend(u8_ios);
        io_events.extend(u16_ios);
        io_events.extend(u32_ios);
        io_events.extend(u64_ios);
        if let Some(xb_ios) = xb_ios {
            io_events.extend(xb_ios);
        }
        Ok((input, io_events))
    }
}

fn record<'a>(codec: Codec) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], AVLRecord> {
    move |input| {
        let (input, timestamp) = be_u64(input)?;
        let (input, priority) = priority(input)?;

        let (input, longitude) = be_i32(input)?;
        let (input, latitude) = be_i32(input)?;
        let (input, altitude) = be_u16(input)?;
        let (input, angle) = be_u16(input)?;
        let (input, satellites) = be_u8(input)?;
        let (input, speed) = be_u16(input)?;

        let (input, trigger_event_id) = event_id(codec)(input)?;
        let (input, generation_type) = cond(codec == Codec::C16, event_generation_cause)(input)?;

        let (input, ios_count) = event_count(codec)(input)?;
        let (input, io_events) = verify(io_events(codec), |events: &Vec<AVLEventIO>| {
            events.len() as u16 == ios_count
        })(input)?;

        // contruct a datetime using the timestamp in since the unix epoch
        let timestamp = Utc.timestamp_millis_opt(timestamp as i64).single().unwrap();

        let longitude = longitude as f64 / 10000000.0;
        let latitude = latitude as f64 / 10000000.0;

        Ok((
            input,
            AVLRecord {
                timestamp,
                priority,
                longitude,
                latitude,
                altitude,
                angle,
                satellites,
                speed,
                trigger_event_id,
                generation_type,
                io_events,
            },
        ))
    }
}

/// # Deprecated
/// Use [`tcp_frame`] instead
#[deprecated(note = "Use tcp_frame instead")]
pub fn tcp_packet(input: &[u8]) -> IResult<&[u8], AVLFrame> {
    tcp_frame(input)
}

/// Parse a TCP teltonika frame
///
///
/// It does 3 main error checks:
/// - Preamble is all zeroes
/// - Both record counts coincide
/// - Computes CRC and verifies it against the one sent
pub fn tcp_frame(input: &[u8]) -> IResult<&[u8], AVLFrame> {
    let (input, _preamble) = tag("\0\0\0\0")(input)?;

    let (input, data) = length_data(be_u32)(input)?;
    let calculated_crc16 = crate::crc16(data);
    let (data, codec) = codec(data)?;
    let (data, records) = length_count(be_u8, record(codec))(data)?;
    let (_data, _records_count) = verify(be_u8, |number_of_records| {
        *number_of_records as usize == records.len()
    })(data)?;

    let (input, crc16) = verify(be_u32, |crc16| *crc16 == calculated_crc16 as u32)(input)?;

    Ok((
        input,
        AVLFrame {
            codec,
            records,
            crc16,
        },
    ))
}

/// Parse an UDP teltonika datagram
///
/// It checks the record counts coincide, parse the whole UDP teltonika channel
pub fn udp_datagram(input: &[u8]) -> IResult<&[u8], AVLDatagram> {
    let (input, packet) = length_data(be_u16)(input)?;
    let (packet, packet_id) = be_u16(packet)?;
    // Non-usable byte
    let (packet, _) = tag("\x01")(packet)?;
    let (packet, avl_packet_id) = be_u8(packet)?;
    let (packet, imei) = imei(packet)?;
    let (packet, codec) = codec(packet)?;
    let (packet, records) = length_count(be_u8, record(codec))(packet)?;
    let (_packet, _records_count) = verify(be_u8, |number_of_records| {
        *number_of_records as usize == records.len()
    })(packet)?;

    Ok((
        input,
        AVLDatagram {
            packet_id,
            avl_packet_id,
            imei,
            codec,
            records,
        },
    ))
}

/// Parse beacon data from variable IO (for AVL ID 548 - Advanced BLE Beacon data)
/// Parse beacon data from variable IO (for AVL ID 548 - Advanced BLE Beacon data)
fn parse_beacon_data_548(input: &[u8]) -> IResult<&[u8], BeaconData> {
    let (input, _constant) = be_u8(input)?; // Should be 0x01
    let mut beacons = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        let (input, beacon_length) = be_u8(remaining)?;
        let (input, beacon_data) = take(beacon_length)(input)?;

        let mut beacon_remaining = beacon_data;
        let mut rssi = 0i8;
        let mut beacon_id_data = Vec::new();
        let mut parameters = Vec::new();

        // Parse beacon parameters according to documentation format
        while !beacon_remaining.is_empty() {
            let (input, param_id) = be_u8(beacon_remaining)?;
            let (input, param_length) = be_u8(input)?;
            let (input, param_data) = take(param_length)(input)?;

            match param_id {
                0x00 => {
                    // RSSI parameter
                    if param_length == 1 {
                        rssi = param_data[0] as i8;
                    }
                }
                0x01 => {
                    // Beacon ID parameter
                    beacon_id_data = param_data.to_vec();
                }
                0x02 => {
                    // Additional data parameter
                    parameters.push(BeaconParameter {
                        id: param_id,
                        value: param_data.to_vec(),
                    });
                }
                _ => {
                    // Unknown parameter
                    parameters.push(BeaconParameter {
                        id: param_id,
                        value: param_data.to_vec(),
                    });
                }
            }

            beacon_remaining = input;
        }

        // Determine beacon type and parse beacon ID based on length
        let (beacon_type, beacon_id) = match beacon_id_data.len() {
            0 => {
                // No beacon ID data present, create a default Eddystone beacon
                (
                    BeaconType::Eddystone,
                    BeaconId::Eddystone {
                        namespace: [0; 10],
                        instance: [0; 6],
                    },
                )
            }
            16 => {
                // Eddystone format (10 bytes namespace + 6 bytes instance)
                let namespace = beacon_id_data[0..10].try_into().unwrap();
                let instance = beacon_id_data[10..16].try_into().unwrap();
                (
                    BeaconType::Eddystone,
                    BeaconId::Eddystone {
                        namespace,
                        instance,
                    },
                )
            }
            20 => {
                // iBeacon format (16 bytes UUID + 2 bytes major + 2 bytes minor)
                let uuid = beacon_id_data[0..16].try_into().unwrap();
                let major = u16::from_be_bytes([beacon_id_data[16], beacon_id_data[17]]);
                let minor = u16::from_be_bytes([beacon_id_data[18], beacon_id_data[19]]);
                (
                    BeaconType::IBeacon,
                    BeaconId::IBeacon { uuid, major, minor },
                )
            }
            _ => {
                // No beacon ID data present or invalid length, create a default Eddystone beacon
                (
                    BeaconType::Eddystone,
                    BeaconId::Eddystone {
                        namespace: [0; 10],
                        instance: [0; 6],
                    },
                )
            }
        };

        beacons.push(BeaconRecord {
            beacon_type,
            beacon_id,
            rssi,
            parameters,
        });

        remaining = input;
    }

    Ok((remaining, BeaconData { beacons }))
}

/// Parse beacon data from variable IO (for AVL IDs 10828, 10829, 10831)
fn parse_beacon_data(input: &[u8]) -> IResult<&[u8], BeaconData> {
    let (input, _constant) = be_u8(input)?;
    let mut beacons = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        let (input, beacon) = parse_beacon_record(remaining)?;
        beacons.push(beacon);
        remaining = input;
    }

    Ok((remaining, BeaconData { beacons }))
}

/// Parse beacon data from variable IO (for AVL ID 385)
fn parse_beacon_data_385(input: &[u8]) -> IResult<&[u8], BeaconData> {
    let mut beacons = Vec::new();
    let mut remaining = input;

    // Skip the initial data part byte
    if !remaining.is_empty() {
        let (input, _data_part) = be_u8(remaining)?;
        remaining = input;
    }

    // Parse all remaining bytes as beacons
    while !remaining.is_empty() {
        let (input, beacon) = parse_beacon_385_common(remaining)?;
        beacons.push(beacon);
        remaining = input;
    }

    Ok((remaining, BeaconData { beacons }))
}

/// Common beacon parsing logic for AVL ID 385
fn parse_beacon_385_common(input: &[u8]) -> IResult<&[u8], BeaconRecord> {
    let (input, beacon_flags) = be_u8(input)?;

    let (beacon_type, id_length) = match beacon_flags {
        0x01 => (BeaconType::Eddystone, 16u8),
        0x21 => (BeaconType::IBeacon, 20u8),
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )))
        }
    };

    let (input, beacon_id_data) = take(id_length)(input)?;
    let (input, rssi) = be_u8(input)?;
    let rssi = rssi as i8;

    let beacon_id = match beacon_type {
        BeaconType::Eddystone => {
            let namespace = beacon_id_data[0..10].try_into().unwrap();
            let instance = beacon_id_data[10..16].try_into().unwrap();
            BeaconId::Eddystone {
                namespace,
                instance,
            }
        }
        BeaconType::IBeacon => {
            let uuid = beacon_id_data[0..16].try_into().unwrap();
            let major = u16::from_be_bytes([beacon_id_data[16], beacon_id_data[17]]);
            let minor = u16::from_be_bytes([beacon_id_data[18], beacon_id_data[19]]);
            BeaconId::IBeacon { uuid, major, minor }
        }
    };

    Ok((
        input,
        BeaconRecord {
            beacon_type,
            beacon_id,
            rssi,
            parameters: Vec::new(),
        },
    ))
}

/// Parse individual beacon record
fn parse_beacon_record(input: &[u8]) -> IResult<&[u8], BeaconRecord> {
    let (input, data_length) = be_u8(input)?;
    let (input, beacon_data) = take(data_length)(input)?;

    let (beacon_data, _rssi_param_id) = be_u8(beacon_data)?;
    let (beacon_data, _rssi_length) = be_u8(beacon_data)?;
    let (beacon_data, rssi) = be_u8(beacon_data)?;
    let rssi = rssi as i8;

    let (beacon_data, _id_param_id) = be_u8(beacon_data)?;
    let (beacon_data, id_length) = be_u8(beacon_data)?;
    let (beacon_data, beacon_id_data) = take(id_length)(beacon_data)?;

    let (beacon_type, beacon_id) = match id_length {
        16 => {
            let namespace = beacon_id_data[0..10].try_into().unwrap();
            let instance = beacon_id_data[10..16].try_into().unwrap();
            (
                BeaconType::Eddystone,
                BeaconId::Eddystone {
                    namespace,
                    instance,
                },
            )
        }
        20 => {
            let uuid = beacon_id_data[0..16].try_into().unwrap();
            let major = u16::from_be_bytes([beacon_id_data[16], beacon_id_data[17]]);
            let minor = u16::from_be_bytes([beacon_id_data[18], beacon_id_data[19]]);
            (
                BeaconType::IBeacon,
                BeaconId::IBeacon { uuid, major, minor },
            )
        }
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::LengthValue,
            )))
        }
    };

    let mut parameters = Vec::new();
    let mut remaining = beacon_data;

    while !remaining.is_empty() {
        let (input, param_id) = be_u8(remaining)?;
        let (input, param_length) = be_u8(input)?;
        let (input, param_value) = take(param_length)(input)?;

        parameters.push(BeaconParameter {
            id: param_id,
            value: param_value.to_vec(),
        });

        remaining = input;
    }

    Ok((
        input,
        BeaconRecord {
            beacon_type,
            beacon_id,
            rssi,
            parameters,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_imei() {
        let input = hex::decode("000F333536333037303432343431303133").unwrap();
        let (input, imei) = imei(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(imei, "356307042441013");
    }

    #[test]
    fn parse_imei_incomplete() {
        let input = hex::decode("000F3335363330373034323434313031").unwrap();
        let err = imei(&input).unwrap_err();
        assert_ne!(input, &[]);

        if let nom::Err::Incomplete(needed) = err {
            assert_eq!(
                needed,
                nom::Needed::Size(std::num::NonZeroUsize::new(1).unwrap())
            );
        } else {
            panic!("Expected Incomplete error");
        }
    }

    #[test]
    fn parse_codec() {
        let input = [0x08];
        let (input, codec) = codec(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(codec, Codec::C8);
    }

    #[test]
    fn parse_priority() {
        let input = [0x00];
        let (input, priority) = priority(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(priority, Priority::Low);
    }

    #[test]
    fn parse_record() {
        let input = hex::decode("0000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000").unwrap();
        let (input, record) = record(Codec::C8)(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            record,
            AVLRecord {
                timestamp: "2019-06-10T10:04:46Z".parse().unwrap(),
                priority: Priority::High,
                longitude: 0.0,
                latitude: 0.0,
                altitude: 0,
                angle: 0,
                satellites: 0,
                speed: 0,
                trigger_event_id: 1,
                generation_type: None,
                io_events: vec![
                    AVLEventIO {
                        id: 21,
                        value: AVLEventIOValue::U8(3,),
                    },
                    AVLEventIO {
                        id: 1,
                        value: AVLEventIOValue::U8(1,),
                    },
                    AVLEventIO {
                        id: 66,
                        value: AVLEventIOValue::U16(24079,),
                    },
                    AVLEventIO {
                        id: 241,
                        value: AVLEventIOValue::U32(24602,),
                    },
                    AVLEventIO {
                        id: 78,
                        value: AVLEventIOValue::U64(0,),
                    },
                ],
            }
        );
    }

    #[test]
    fn parse_record_incomplete() {
        let input = hex::decode("0000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E00000000000000").unwrap();
        let err = record(Codec::C8)(&input).unwrap_err();
        assert_ne!(input, &[]);

        if let nom::Err::Incomplete(needed) = err {
            assert_eq!(
                needed,
                nom::Needed::Size(std::num::NonZeroUsize::new(1).unwrap())
            );
        } else {
            panic!("Expected Incomplete error");
        }
    }

    #[test]
    fn parse_frame_codec8_1() {
        let input = hex::decode("000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            frame,
            AVLFrame {
                codec: Codec::C8,
                records: vec![AVLRecord {
                    timestamp: "2019-06-10T10:04:46Z".parse().unwrap(),
                    priority: Priority::High,
                    longitude: 0.0,
                    latitude: 0.0,
                    altitude: 0,
                    angle: 0,
                    satellites: 0,
                    speed: 0,
                    trigger_event_id: 1,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 21,
                            value: AVLEventIOValue::U8(3,),
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1,),
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(24079,),
                        },
                        AVLEventIO {
                            id: 241,
                            value: AVLEventIOValue::U32(24602,),
                        },
                        AVLEventIO {
                            id: 78,
                            value: AVLEventIOValue::U64(0,),
                        },
                    ],
                },],
                crc16: 51151,
            }
        );
    }

    #[test]
    fn parse_frame_codec8_2() {
        let input = hex::decode("000000000000002808010000016B40D9AD80010000000000000000000000000000000103021503010101425E100000010000F22A").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            frame,
            AVLFrame {
                codec: Codec::C8,
                records: vec![AVLRecord {
                    timestamp: "2019-06-10T10:05:36Z".parse().unwrap(),
                    priority: Priority::High,
                    longitude: 0.0,
                    latitude: 0.0,
                    altitude: 0,
                    angle: 0,
                    satellites: 0,
                    speed: 0,
                    trigger_event_id: 1,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 21,
                            value: AVLEventIOValue::U8(3,),
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1,),
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(24080,),
                        },
                    ],
                },],
                crc16: 61994,
            }
        );
    }

    #[test]
    fn parse_frame_codec8_3() {
        let input = hex::decode("000000000000004308020000016B40D57B480100000000000000000000000000000001010101000000000000016B40D5C198010000000000000000000000000000000101010101000000020000252C").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            frame,
            AVLFrame {
                codec: Codec::C8,
                records: vec![
                    AVLRecord {
                        timestamp: "2019-06-10T10:01:01Z".parse().unwrap(),
                        priority: Priority::High,
                        longitude: 0.0,
                        latitude: 0.0,
                        altitude: 0,
                        angle: 0,
                        satellites: 0,
                        speed: 0,
                        trigger_event_id: 1,
                        generation_type: None,
                        io_events: vec![AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(0,),
                        },],
                    },
                    AVLRecord {
                        timestamp: "2019-06-10T10:01:19Z".parse().unwrap(),
                        priority: Priority::High,
                        longitude: 0.0,
                        latitude: 0.0,
                        altitude: 0,
                        angle: 0,
                        satellites: 0,
                        speed: 0,
                        trigger_event_id: 1,
                        generation_type: None,
                        io_events: vec![AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1,),
                        },],
                    },
                ],
                crc16: 9516,
            }
        );
    }

    #[test]
    fn parse_frame_codec8ext() {
        let input = hex::decode("000000000000004A8E010000016B412CEE000100000000000000000000000000000000010005000100010100010011001D00010010015E2C880002000B000000003544C87A000E000000001DD7E06A00000100002994").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            frame,
            AVLFrame {
                codec: Codec::C8Ext,
                records: vec![AVLRecord {
                    timestamp: "2019-06-10T11:36:32Z".parse().unwrap(),
                    priority: Priority::High,
                    longitude: 0.0,
                    latitude: 0.0,
                    altitude: 0,
                    angle: 0,
                    satellites: 0,
                    speed: 0,
                    trigger_event_id: 1,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1,),
                        },
                        AVLEventIO {
                            id: 17,
                            value: AVLEventIOValue::U16(29,),
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(22949000,),
                        },
                        AVLEventIO {
                            id: 11,
                            value: AVLEventIOValue::U64(893700218,),
                        },
                        AVLEventIO {
                            id: 14,
                            value: AVLEventIOValue::U64(500686954,),
                        },
                    ],
                },],
                crc16: 10644,
            }
        );
    }

    #[test]
    fn parse_frame_codec16() {
        let input = hex::decode("000000000000005F10020000016BDBC7833000000000000000000000000000000000000B05040200010000030002000B00270042563A00000000016BDBC7871800000000000000000000000000000000000B05040200010000030002000B00260042563A00000200005FB3").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            frame,
            AVLFrame {
                codec: Codec::C16,
                records: vec![
                    AVLRecord {
                        timestamp: "2019-07-10T12:06:54Z".parse().unwrap(),
                        priority: Priority::Low,
                        longitude: 0.0,
                        latitude: 0.0,
                        altitude: 0,
                        angle: 0,
                        satellites: 0,
                        speed: 0,
                        trigger_event_id: 11,
                        generation_type: Some(EventGenerationCause::OnChange),
                        io_events: vec![
                            AVLEventIO {
                                id: 1,
                                value: AVLEventIOValue::U8(0)
                            },
                            AVLEventIO {
                                id: 3,
                                value: AVLEventIOValue::U8(0)
                            },
                            AVLEventIO {
                                id: 11,
                                value: AVLEventIOValue::U16(39)
                            },
                            AVLEventIO {
                                id: 66,
                                value: AVLEventIOValue::U16(22074)
                            }
                        ]
                    },
                    AVLRecord {
                        timestamp: "2019-07-10T12:06:55Z".parse().unwrap(),
                        priority: Priority::Low,
                        longitude: 0.0,
                        latitude: 0.0,
                        altitude: 0,
                        angle: 0,
                        satellites: 0,
                        speed: 0,
                        trigger_event_id: 11,
                        generation_type: Some(EventGenerationCause::OnChange),
                        io_events: vec![
                            AVLEventIO {
                                id: 1,
                                value: AVLEventIOValue::U8(0)
                            },
                            AVLEventIO {
                                id: 3,
                                value: AVLEventIOValue::U8(0)
                            },
                            AVLEventIO {
                                id: 11,
                                value: AVLEventIOValue::U16(38)
                            },
                            AVLEventIO {
                                id: 66,
                                value: AVLEventIOValue::U16(22074)
                            }
                        ]
                    }
                ],
                crc16: 24499
            }
        );
    }

    #[test]
    fn parse_udp_datagram() {
        let input = hex::decode("003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001").unwrap();
        let (input, datagram) = udp_datagram(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            datagram,
            AVLDatagram {
                packet_id: 0xCAFE,
                avl_packet_id: 0x05,
                imei: String::from("\x33\x35\x32\x30\x39\x33\x30\x38\x36\x34\x30\x33\x36\x35\x35"),
                codec: Codec::C8,
                records: vec![AVLRecord {
                    timestamp: "2019-06-13T06:23:26Z".parse().unwrap(),
                    priority: Priority::High,
                    longitude: 0.0,
                    latitude: 0.0,
                    altitude: 0,
                    angle: 0,
                    satellites: 0,
                    speed: 0,
                    trigger_event_id: 0x01,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 0x15,
                            value: AVLEventIOValue::U8(0x03)
                        },
                        AVLEventIO {
                            id: 0x01,
                            value: AVLEventIOValue::U8(0x01)
                        },
                        AVLEventIO {
                            id: 0x42,
                            value: AVLEventIOValue::U16(0x5DBC)
                        },
                    ]
                }],
            }
        )
    }

    #[test]
    fn parse_udp_datagram_incomplete() {
        let input = hex::decode("003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC00").unwrap();
        let err = udp_datagram(&input).unwrap_err();
        assert_ne!(input, &[]);

        if let nom::Err::Incomplete(needed) = err {
            assert_eq!(
                needed,
                nom::Needed::Size(std::num::NonZeroUsize::new(2).unwrap())
            );
        } else {
            panic!("Expected Incomplete error");
        }
    }

    #[test]
    fn parse_negative_emisphere_coordinates() {
        let input = hex::decode("00000000000000460801000001776D58189001FA0A1F00F1194D80009C009D05000F9B0D06EF01F0001505C80045019B0105B5000BB6000A424257430F8044000002F1000060191000000BE1000100006E2B").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(frame.records[0].longitude, -10.0);
        assert_eq!(frame.records[0].latitude, -25.0);
    }

    #[test]
    fn parse_beacon_eddystone() {
        let input = hex::decode(
            "00000000000004db8e0800000199b9f7e8cb0010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d8030001ac030001d1030001db030001d1030001d4030001c6030001b3030001aa030001af030001d3030001af030001b2030001cc030001b4030001b4030001d9030001d9030001c8030001cb030001cd030001ba030001b4030001dc030001d2030001cb030001d6030001d400000199b9f7ecb30010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d9030001ac030001d1030001db030001d1030001d5030001c6030001b3030001aa030001ae030001d3030001ad030001b2030001cd030001b0030001ba030001d9030001d9030001c7030001cb030001cd030001ba030001b4030001dc030001d1030001ca030001d6030001d400000199b9f7f09b0010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d9030001ac030001d1030001db030001d1030001d6030001c6030001b3030001aa030001ad030001d3030001ab030001b2030001cd030001af030001bc030001d9030001d9030001c7030001cb030001cd030001ba030001b4030001dc030001d0030001c9030001d6030001d400000199b9f8080b0010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d4030001aa030001d1030001db030001d9030001d3030001c6030001b3030001b9030001ad030001d3030001aa030001b4030001c9030001b8030001be030001d7030001d7030001cc030001cd030001cd030001b5030001b3030001db030001d6030001d2030001d6030001d400000199b9f808150010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d4030001aa030001d1030001db030001d9030001d3030001c6030001b3030001b9030001ad030001d3030001aa030001b4030001c9030001b8030001be030001d7030001d7030001cc030001cd030001cd030001b5030001b3030001db030001d6030001d2030001d6030001d400000199b9f8081f0010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d4030001aa030001d1030001db030001d9030001d3030001c6030001b3030001b9030001ad030001d3030001aa030001b4030001c9030001b8030001be030001d7030001d7030001cc030001cd030001cd030001b5030001b3030001db030001d6030001d2030001d6030001d400000199b9f808290010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d4030001aa030001d0030001da030001d9030001d3030001c6030001b3030001b9030001ad030001d3030001aa030001b4030001c9030001b8030001be030001d7030001d7030001cd030001cd030001cd030001b4030001b3030001db030001d6030001d2030001d6030001d400000199b9f808330010aff6b8f0719d500000000000000002240001000000000000000000010224007101030001d4030001aa030001d0030001da030001d9030001d3030001c6030001b3030001b9030001ad030001d3030001aa030001b4030001c9030001b8030001be030001d7030001d7030001cd030001cc030001cd030001b4030001b3030001db030001d6030001d2030001d6030001d4080000b93a",
        )
        .unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);

        dbg!(&frame);

        // Just verify that we can successfully parse the data as beacon data
        if let AVLEventIOValue::Beacon(beacon_data) = &frame.records[0].io_events[0].value {
            // Successfully parsed as beacon data
            println!("Successfully parsed {} beacons", beacon_data.beacons.len());
        } else {
            panic!("Expected beacon data");
        }
    }

    #[test]
    fn parse_beacon_10831() {
        let input = hex::decode("000000000000004b8e010000018368952793000f0e54fc209ab05800b300b40e00002a4f0001000000000000000000012a4f001e011c0001a40110eb47706aa38255aa96f21a154e2d00550d01000e020bd6010000823f").unwrap();
        let (input, frame) = tcp_frame(&input).unwrap();
        assert_eq!(input, &[]);

        if let AVLEventIOValue::Beacon(beacon_data) = &frame.records[0].io_events[0].value {
            assert_eq!(beacon_data.beacons.len(), 1);
            let beacon = &beacon_data.beacons[0];
            assert_eq!(beacon.beacon_type, BeaconType::Eddystone);
            assert_eq!(beacon.rssi, -92);
            if let BeaconId::Eddystone {
                namespace,
                instance,
            } = &beacon.beacon_id
            {
                assert_eq!(
                    namespace,
                    &[0xeb, 0x47, 0x70, 0x6a, 0xa3, 0x82, 0x55, 0xaa, 0x96, 0xf2]
                );
                assert_eq!(instance, &[0x1a, 0x15, 0x4e, 0x2d, 0x00, 0x55]);
            } else {
                panic!("Expected Eddystone beacon ID");
            }
            assert_eq!(beacon.parameters.len(), 2);
        } else {
            panic!("Expected beacon data");
        }
    }

    #[test]
    fn parse_command_response() {
        let input = [
            0u8, 0, 0, 0, 0, 0, 0, 160, 12, 1, 6, 0, 0, 0, 152, 82, 84, 67, 58, 50, 48, 50, 52, 47,
            55, 47, 49, 49, 32, 49, 49, 58, 51, 51, 32, 73, 110, 105, 116, 58, 50, 48, 50, 52, 47,
            54, 47, 54, 32, 56, 58, 51, 48, 32, 85, 112, 84, 105, 109, 101, 58, 51, 48, 50, 57, 52,
            57, 52, 115, 32, 80, 87, 82, 58, 65, 98, 110, 111, 114, 109, 97, 108, 32, 82, 83, 84,
            58, 49, 32, 71, 80, 83, 58, 51, 32, 83, 65, 84, 58, 49, 55, 32, 84, 84, 70, 70, 58, 52,
            32, 84, 84, 76, 70, 58, 51, 32, 78, 79, 71, 80, 83, 58, 48, 58, 48, 32, 83, 82, 58, 56,
            51, 49, 56, 53, 32, 70, 71, 58, 48, 32, 70, 76, 58, 52, 52, 32, 83, 77, 83, 58, 48, 32,
            82, 69, 67, 58, 48, 32, 77, 68, 58, 48, 32, 68, 66, 58, 48, 1, 0, 0, 220, 144,
        ];

        assert_eq!(
            command_response(&input),
            Ok((
                [].as_slice(),
                [
                    82u8, 84, 67, 58, 50, 48, 50, 52, 47, 55, 47, 49, 49, 32, 49, 49, 58, 51, 51,
                    32, 73, 110, 105, 116, 58, 50, 48, 50, 52, 47, 54, 47, 54, 32, 56, 58, 51, 48,
                    32, 85, 112, 84, 105, 109, 101, 58, 51, 48, 50, 57, 52, 57, 52, 115, 32, 80,
                    87, 82, 58, 65, 98, 110, 111, 114, 109, 97, 108, 32, 82, 83, 84, 58, 49, 32,
                    71, 80, 83, 58, 51, 32, 83, 65, 84, 58, 49, 55, 32, 84, 84, 70, 70, 58, 52, 32,
                    84, 84, 76, 70, 58, 51, 32, 78, 79, 71, 80, 83, 58, 48, 58, 48, 32, 83, 82, 58,
                    56, 51, 49, 56, 53, 32, 70, 71, 58, 48, 32, 70, 76, 58, 52, 52, 32, 83, 77, 83,
                    58, 48, 32, 82, 69, 67, 58, 48, 32, 77, 68, 58, 48, 32, 68, 66, 58, 48
                ]
                .as_slice()
            ))
        );
    }
}
