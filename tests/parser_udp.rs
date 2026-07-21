mod common;

use common::*;
use nom_teltonika::*;

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
