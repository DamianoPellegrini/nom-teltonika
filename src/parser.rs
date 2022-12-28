use core::panic;

use chrono::{TimeZone, Utc};
use nom::{
    character::complete::anychar,
    combinator::cond,
    error::ParseError,
    multi::{count, length_count},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    IResult, Parser,
};

use crate::{
    AVLEventIO, AVLEventIOValue, AVLRecord, AVLTCPPacket, Codec, GenerationType, Priority,
};

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

fn generation_type(input: &[u8]) -> IResult<&[u8], GenerationType> {
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

fn record<'a>(codec: Codec) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], AVLRecord> {
    move |input| {
        let (input, timestamp) = be_u64(input)?;
        let (input, priority) = priority(input)?;

        let (input, longitude) = be_u32(input)?;
        let (input, latitude) = be_u32(input)?;
        let (input, altitude) = be_u16(input)?;
        let (input, angle) = be_u16(input)?;
        let (input, satellites) = be_u8(input)?;
        let (input, speed) = be_u16(input)?;

        let (input, trigger_event_id) = event_id(codec)(input)?;
        let (input, generation_type) = cond(codec == Codec::C16, generation_type)(input)?;

        let (input, ios_count) = event_count(codec)(input)?;

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
                event(codec, length_count(event_count(codec), be_u8)).map(|(id, val)| AVLEventIO {
                    id,
                    value: AVLEventIOValue::Variable(val),
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

        if io_events.len() != ios_count as usize {
            panic!("wrong count");
        }

        // contruct a datetime using the timestamp in since the unix epoch
        let datetime = Utc.timestamp_millis_opt(timestamp as i64).single().unwrap();

        let longitude = if longitude & 0x80000000 != 0 {
            longitude as i32 * -1
        } else {
            longitude as i32
        } as f64
            / 10000000.0;
        let latitude = if latitude & 0x80000000 != 0 {
            latitude as i32 * -1
        } else {
            latitude as i32
        } as f64
            / 10000000.0;

        Ok((
            input,
            AVLRecord {
                datetime: datetime,
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

pub fn packet(input: &[u8]) -> IResult<&[u8], AVLTCPPacket> {
    let (input, preamble) = be_u32(input)?;

    if preamble != 0x00000000 {
        panic!("wrong preamble");
    }

    let (input, data_field_len) = be_u32(input)?;
    let calculated_crc16 = crate::crc16(&input[0..data_field_len as usize]);
    let (input, codec) = codec(input)?;
    let (input, number_of_records) = be_u8(input)?;
    let (input, records) = count(record(codec), number_of_records as usize)(input)?;
    let (input, number_of_records_redundancy) = be_u8(input)?;
    if number_of_records != number_of_records_redundancy {
        panic!("wrong number of records");
    }
    let (input, crc16) = be_u32(input)?;

    if crc16 != calculated_crc16 as u32 {
        panic!("wrong crc16");
    }

    Ok((
        input,
        AVLTCPPacket {
            preamble,
            data_field_len,
            codec,
            records,
            crc16,
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
                datetime: "2019-06-10T10:04:46Z".parse().unwrap(),
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
    fn parse_packet_codec8_1() {
        let input = hex::decode("000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF").unwrap();
        let (input, packet) = packet(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            packet,
            AVLTCPPacket {
                preamble: 0,
                data_field_len: 54,
                codec: Codec::C8,
                records: vec![AVLRecord {
                    datetime: "2019-06-10T10:04:46Z".parse().unwrap(),
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
    fn parse_packet_codec8_2() {
        let input = hex::decode("000000000000002808010000016B40D9AD80010000000000000000000000000000000103021503010101425E100000010000F22A").unwrap();
        let (input, packet) = packet(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            packet,
            AVLTCPPacket {
                preamble: 0,
                data_field_len: 40,
                codec: Codec::C8,
                records: vec![AVLRecord {
                    datetime: "2019-06-10T10:05:36Z".parse().unwrap(),
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
    fn parse_packet_codec8_3() {
        let input = hex::decode("000000000000004308020000016B40D57B480100000000000000000000000000000001010101000000000000016B40D5C198010000000000000000000000000000000101010101000000020000252C").unwrap();
        let (input, packet) = packet(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            packet,
            AVLTCPPacket {
                preamble: 0,
                data_field_len: 67,
                codec: Codec::C8,
                records: vec![
                    AVLRecord {
                        datetime: "2019-06-10T10:01:01Z".parse().unwrap(),
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
                        datetime: "2019-06-10T10:01:19Z".parse().unwrap(),
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
    fn parse_packet_codec8ext() {
        let input = hex::decode("000000000000004A8E010000016B412CEE000100000000000000000000000000000000010005000100010100010011001D00010010015E2C880002000B000000003544C87A000E000000001DD7E06A00000100002994").unwrap();
        let (input, packet) = packet(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            packet,
            AVLTCPPacket {
                preamble: 0,
                data_field_len: 74,
                codec: Codec::C8Ext,
                records: vec![AVLRecord {
                    datetime: "2019-06-10T11:36:32Z".parse().unwrap(),
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
    fn parse_packet_codec16() {
        let input = hex::decode("000000000000005F10020000016BDBC7833000000000000000000000000000000000000B05040200010000030002000B00270042563A00000000016BDBC7871800000000000000000000000000000000000B05040200010000030002000B00260042563A00000200005FB3").unwrap();
        let (input, packet) = packet(&input).unwrap();
        assert_eq!(input, &[]);
        assert_eq!(
            packet,
            AVLTCPPacket {
                preamble: 0,
                data_field_len: 95,
                codec: Codec::C16,
                records: vec![
                    AVLRecord {
                        datetime: "2019-07-10T12:06:54Z".parse().unwrap(),
                        priority: Priority::Low,
                        longitude: 0.0,
                        latitude: 0.0,
                        altitude: 0,
                        angle: 0,
                        satellites: 0,
                        speed: 0,
                        trigger_event_id: 11,
                        generation_type: Some(GenerationType::OnChange),
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
                        datetime: "2019-07-10T12:06:55Z".parse().unwrap(),
                        priority: Priority::Low,
                        longitude: 0.0,
                        latitude: 0.0,
                        altitude: 0,
                        angle: 0,
                        satellites: 0,
                        speed: 0,
                        trigger_event_id: 11,
                        generation_type: Some(GenerationType::OnChange),
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
}
