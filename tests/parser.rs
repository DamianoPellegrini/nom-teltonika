use std::{fs::File, io::Read};

use nom_teltonika::*;

#[test]
fn parse_file() {
    // Load test.bin
    let mut file = File::open("tests/test.bin").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    // Parse test.bin
    let (_, packet) = parser::tcp_frame(&buffer).unwrap();
    assert_eq!(
        packet,
        AVLFrame {
            codec: Codec::C8Ext,
            records: vec![
                AVLRecord {
                    timestamp: "2021-06-10T14:08:01Z".parse().unwrap(),
                    priority: Priority::Low,
                    longitude: 12.4534033,
                    latitude: 44.0640849,
                    altitude: 35,
                    angle: 214,
                    satellites: 14,
                    speed: 0,
                    trigger_event_id: 0,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 239,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 240,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 200,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 179,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 2,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 180,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 246,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(12896)
                        },
                        AVLEventIO {
                            id: 67,
                            value: AVLEventIOValue::U16(4100)
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(3661976)
                        }
                    ]
                },
                AVLRecord {
                    timestamp: "2021-06-10T14:08:06Z".parse().unwrap(),
                    priority: Priority::Low,
                    longitude: 12.4534033,
                    latitude: 44.0640849,
                    altitude: 35,
                    angle: 214,
                    satellites: 14,
                    speed: 0,
                    trigger_event_id: 0,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 239,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 240,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 200,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 179,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 2,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 180,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 246,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(12855)
                        },
                        AVLEventIO {
                            id: 67,
                            value: AVLEventIOValue::U16(4099)
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(3661976)
                        }
                    ]
                },
                AVLRecord {
                    timestamp: "2021-06-10T14:08:11Z".parse().unwrap(),
                    priority: Priority::Low,
                    longitude: 12.4534033,
                    latitude: 44.0640849,
                    altitude: 35,
                    angle: 214,
                    satellites: 13,
                    speed: 0,
                    trigger_event_id: 0,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 239,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 240,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 200,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 179,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 2,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 180,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 246,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(12956)
                        },
                        AVLEventIO {
                            id: 67,
                            value: AVLEventIOValue::U16(4099)
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(3661976)
                        }
                    ]
                },
                AVLRecord {
                    timestamp: "2021-06-10T14:08:16Z".parse().unwrap(),
                    priority: Priority::Low,
                    longitude: 12.4534033,
                    latitude: 44.0640849,
                    altitude: 35,
                    angle: 214,
                    satellites: 13,
                    speed: 0,
                    trigger_event_id: 0,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 239,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 240,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 200,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 179,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 2,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 180,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 246,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(12816)
                        },
                        AVLEventIO {
                            id: 67,
                            value: AVLEventIOValue::U16(4099)
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(3661976)
                        }
                    ]
                },
                AVLRecord {
                    timestamp: "2021-06-10T14:08:21Z".parse().unwrap(),
                    priority: Priority::Low,
                    longitude: 12.4534033,
                    latitude: 44.0640849,
                    altitude: 35,
                    angle: 214,
                    satellites: 13,
                    speed: 0,
                    trigger_event_id: 0,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 239,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 240,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 200,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 179,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 2,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 180,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 246,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(12849)
                        },
                        AVLEventIO {
                            id: 67,
                            value: AVLEventIOValue::U16(4099)
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(3661976)
                        }
                    ]
                },
                AVLRecord {
                    timestamp: "2021-06-10T14:08:26Z".parse().unwrap(),
                    priority: Priority::Low,
                    longitude: 12.4534033,
                    latitude: 44.0640849,
                    altitude: 35,
                    angle: 214,
                    satellites: 13,
                    speed: 0,
                    trigger_event_id: 0,
                    generation_type: None,
                    io_events: vec![
                        AVLEventIO {
                            id: 239,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 240,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 200,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 1,
                            value: AVLEventIOValue::U8(1)
                        },
                        AVLEventIO {
                            id: 179,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 2,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 180,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 246,
                            value: AVLEventIOValue::U8(0)
                        },
                        AVLEventIO {
                            id: 66,
                            value: AVLEventIOValue::U16(12904)
                        },
                        AVLEventIO {
                            id: 67,
                            value: AVLEventIOValue::U16(4099)
                        },
                        AVLEventIO {
                            id: 16,
                            value: AVLEventIOValue::U32(3661976)
                        }
                    ]
                }
            ],
            crc16: 6333
        }
    );
}
