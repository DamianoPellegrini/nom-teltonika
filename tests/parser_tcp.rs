mod common;

use std::num::NonZeroUsize;

use common::*;
use nom_teltonika::{encode::*, parser::*, protocol::*};

#[test]
fn should_parse_valid_imei_when_handshake_is_complete() {
    let parsed = parse_imei(&bytes("000F333536333037303432343431303133")).unwrap();
    assert_eq!(parsed.value.as_str(), "356307042441013");
    assert_eq!(parsed.consumed, 17);
}

#[test]
fn should_reject_imei_when_digits_are_invalid() {
    let error = parse_imei(&bytes("000F33353633303730343234343130313A")).unwrap_err();
    assert!(matches!(
        error,
        ParseError::Rejected {
            consumed: 17,
            reason: RejectionReason::InvalidImei,
            ..
        }
    ));
}

#[test]
fn should_report_exact_need_when_imei_is_truncated() {
    assert_eq!(
        parse_imei(&bytes("000F333536")).unwrap_err(),
        ParseError::Incomplete {
            needed: NonZeroUsize::new(12).unwrap()
        }
    );
}

#[test]
fn should_parse_all_supported_avl_codecs() {
    for (fixture, codec, count) in [
        (CODEC8, AvlCodec::Codec8, 1),
        (CODEC8_EXTENDED, AvlCodec::Codec8Extended, 1),
        (CODEC16, AvlCodec::Codec16, 2),
    ] {
        let input = bytes(fixture);
        let parsed = parse_tcp_frame(&input).unwrap();
        let Frame::Avl(packet) = parsed.value else {
            panic!("expected AVL")
        };
        assert_eq!(packet.codec(), codec);
        assert_eq!(packet.records().len(), count);
        assert_eq!(parsed.consumed, input.len());
    }
}

#[test]
fn should_preserve_wire_values_in_owned_result() {
    let Frame::Avl(packet) = parse_tcp_frame(&bytes(CODEC8)).unwrap().value else {
        panic!("expected AVL")
    };
    let record = &packet.records()[0];
    assert_eq!(record.timestamp.unix_millis(), 1_560_161_086_000);
    assert_eq!(record.gps.longitude_raw, 0);
    assert_eq!(record.io_elements.len(), 5);
}

#[test]
fn should_preserve_anomalous_coordinates_without_rejecting_frame() {
    let mut input = bytes(CODEC8);
    input[19..23].copy_from_slice(&i32::MAX.to_be_bytes());
    input[23..27].copy_from_slice(&i32::MIN.to_be_bytes());
    repair_crc(&mut input);
    let Frame::Avl(packet) = parse_tcp_frame(&input).unwrap().value else {
        panic!()
    };
    let gps = packet.records()[0].gps;
    assert_eq!(gps.longitude_raw, i32::MAX);
    assert_eq!(gps.latitude_raw, i32::MIN);
    assert!(!gps.is_position_valid());
}

#[test]
fn should_return_incomplete_at_every_tcp_truncation_position() {
    for fixture in [CODEC8, CODEC8_EXTENDED, CODEC16, CODEC12_COMMAND] {
        let input = bytes(fixture);
        for end in 0..input.len() {
            assert!(matches!(
                parse_tcp_frame(&input[..end]),
                Err(ParseError::Incomplete { .. })
            ));
        }
    }
}

#[test]
fn should_consume_only_first_frame_when_frames_are_concatenated() {
    let first = bytes(CODEC8);
    let mut input = first.clone();
    input.extend_from_slice(&bytes(CODEC12_COMMAND)[..7]);
    assert_eq!(parse_tcp_frame(&input).unwrap().consumed, first.len());
}

#[test]
fn should_reject_and_consume_delimited_crc_mismatch() {
    let mut input = bytes(CODEC8);
    let total = input.len();
    input[total - 1] ^= 1;
    assert!(
        matches!(parse_tcp_frame(&input), Err(ParseError::Rejected { consumed, reason: RejectionReason::CrcMismatch { .. }, .. }) if consumed == total)
    );
}

#[test]
fn should_reject_avl_duplicate_count_mismatch() {
    let mut input = bytes(CODEC8);
    let second_count = input.len() - 5;
    input[second_count] = 2;
    repair_crc(&mut input);
    assert!(matches!(
        parse_tcp_frame(&input),
        Err(ParseError::Rejected {
            reason: RejectionReason::RecordCountMismatch {
                first: 1,
                second: 2
            },
            ..
        })
    ));
}

#[test]
fn should_reject_invalid_priority_generation_and_io_count() {
    let mut priority = bytes(CODEC8);
    priority[18] = 3;
    repair_crc(&mut priority);
    assert!(matches!(
        parse_tcp_frame(&priority),
        Err(ParseError::Rejected {
            reason: RejectionReason::InvalidPriority { value: 3 },
            ..
        })
    ));

    let mut generation = bytes(CODEC16);
    generation[36] = 9;
    repair_crc(&mut generation);
    assert!(matches!(
        parse_tcp_frame(&generation),
        Err(ParseError::Rejected {
            reason: RejectionReason::InvalidGenerationType { value: 9 },
            ..
        })
    ));

    let mut io_count = bytes(CODEC8);
    io_count[35] = 6;
    repair_crc(&mut io_count);
    assert!(matches!(
        parse_tcp_frame(&io_count),
        Err(ParseError::Rejected {
            reason: RejectionReason::IoCountMismatch {
                declared: 6,
                decoded: 5
            },
            ..
        })
    ));
}

#[test]
fn should_copy_variable_codec8_extended_io_bytes_once_into_owned_value() {
    let mut data = vec![0x8e, 1];
    data.extend_from_slice(&[0; 8]);
    data.push(0);
    data.extend_from_slice(&[0; 15]);
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    for _ in 0..4 {
        data.extend_from_slice(&0u16.to_be_bytes());
    }
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0x1234u16.to_be_bytes());
    data.extend_from_slice(&3u16.to_be_bytes());
    data.extend_from_slice(&[0xff, 0, 0x80]);
    data.push(1);

    let Frame::Avl(packet) = parse_tcp_frame(&tcp_frame_from_data(&data)).unwrap().value else {
        panic!()
    };
    assert!(matches!(
        packet.records()[0].io_elements[0].value,
        IoValue::Bytes(ref value) if value == &[0xff, 0, 0x80]
    ));
}

#[test]
fn should_fail_immediately_when_declared_frame_exceeds_limit() {
    let mut header = vec![0; 9];
    header[4..8].copy_from_slice(&10_000u32.to_be_bytes());
    header[8] = 0x08;
    assert!(matches!(
        parse_tcp_frame(&header),
        Err(ParseError::Fatal {
            reason: FatalReason::FrameTooLarge { .. },
            ..
        })
    ));
}

#[test]
fn should_treat_untrusted_preamble_as_fatal() {
    let mut input = bytes(CODEC8);
    input[0] = 1;
    assert!(matches!(
        parse_tcp_frame(&input),
        Err(ParseError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidPreamble
        })
    ));
}

#[test]
fn should_parse_codec12_binary_batch_other_type_and_count_mismatch() {
    let binary = [0xff, 0x00, 0x80];
    let batch = encode_codec12_commands([binary.as_slice(), b"getinfo".as_slice()]);
    let Frame::Codec12(packet) = parse_tcp_frame(&batch).unwrap().value else {
        panic!()
    };
    assert!(matches!(packet.message(), Codec12Message::Command(payloads) if payloads[0] == binary));

    let mut other = batch;
    other[10] = 0x7f;
    other[18] = 0x7f;
    let second_count = other.len() - 5;
    other[second_count] = 1;
    repair_crc(&mut other);
    let Frame::Codec12(packet) = parse_tcp_frame(&other).unwrap().value else {
        panic!()
    };
    assert_eq!(
        packet.count_status(),
        CountStatus::Mismatched {
            first: 2,
            second: 1
        }
    );
    assert!(matches!(
        packet.message(),
        Codec12Message::Other { type_id: 0x7f, .. }
    ));
    assert!(matches!(packet.message().payload_as_str(0), Some(Err(_))));
    assert!(packet.message().payload_as_str(99).is_none());

    let mut response = encode_codec12_command(b"ok");
    response[10] = 0x06;
    repair_crc(&mut response);
    let Frame::Codec12(packet) = parse_tcp_frame(&response).unwrap().value else {
        panic!()
    };
    assert!(matches!(packet.message(), Codec12Message::Response(_)));
}

#[test]
fn should_match_official_codec12_encoder_example() {
    assert_eq!(encode_codec12_command(b"getinfo"), bytes(CODEC12_COMMAND));
}
