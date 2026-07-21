mod common;

use common::*;
use nom_teltonika::{encode::encode_udp_ack, parser::*};

#[test]
fn should_return_incomplete_at_every_udp_truncation_position() {
    let input = bytes(UDP_CODEC8);
    for end in 0..input.len() {
        assert!(matches!(
            parse_udp_datagram(&input[..end]),
            Err(ParseError::Incomplete { .. })
        ));
    }
}

#[test]
fn should_parse_official_udp_datagram_and_encode_correlated_ack() {
    let input = bytes(UDP_CODEC8);
    let parsed = parse_udp_datagram(&input).unwrap();
    assert_eq!(parsed.value.channel_packet_id(), 0xcafe);
    assert_eq!(parsed.value.avl_packet_id(), 5);
    assert_eq!(parsed.value.imei().as_str(), "352093086403655");
    assert_eq!(encode_udp_ack(0xcafe, 5, 1), [0, 5, 0xca, 0xfe, 1, 5, 1]);
}

#[test]
fn should_reject_invalid_udp_imei_at_wire_offset() {
    let mut invalid_length = bytes(UDP_CODEC8);
    invalid_length[7] = 14;
    assert!(matches!(
        parse_udp_datagram(&invalid_length),
        Err(ParseError::Rejected {
            offset: 6,
            reason: RejectionReason::InvalidImei,
            ..
        })
    ));

    let mut invalid_digit = bytes(UDP_CODEC8);
    invalid_digit[8] = b'x';
    assert!(matches!(
        parse_udp_datagram(&invalid_digit),
        Err(ParseError::Rejected {
            offset: 8,
            reason: RejectionReason::InvalidImei,
            ..
        })
    ));
}
