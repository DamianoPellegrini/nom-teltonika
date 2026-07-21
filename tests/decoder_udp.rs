mod common;

use common::*;
use nom_teltonika::{decoder::*, encoder::encode_udp_ack};

#[test]
fn should_distinguish_short_header_from_length_mismatch() {
    assert_eq!(
        decode_udp_datagram(&[]).unwrap_err(),
        UdpDecodeError::TruncatedHeader { actual: 0 }
    );
    assert_eq!(
        decode_udp_datagram(&[0]).unwrap_err(),
        UdpDecodeError::TruncatedHeader { actual: 1 }
    );

    let input = bytes(UDP_CODEC8);
    assert_eq!(
        decode_udp_datagram(&input[..input.len() - 1]).unwrap_err(),
        UdpDecodeError::LengthMismatch {
            declared: input.len(),
            actual: input.len() - 1,
        }
    );
    let mut trailing = input.clone();
    trailing.push(0);
    assert_eq!(
        decode_udp_datagram(&trailing).unwrap_err(),
        UdpDecodeError::LengthMismatch {
            declared: input.len(),
            actual: input.len() + 1,
        }
    );
}

#[test]
fn should_decode_official_udp_datagram_and_encode_correlated_ack() {
    let input = bytes(UDP_CODEC8);
    let datagram = decode_udp_datagram(&input).unwrap();
    assert_eq!(datagram.channel_packet_id(), 0xcafe);
    assert_eq!(datagram.avl_packet_id(), 5);
    assert_eq!(datagram.imei().as_str(), "352093086403655");
    assert_eq!(encode_udp_ack(0xcafe, 5, 1), [0, 5, 0xca, 0xfe, 1, 5, 1]);
}

#[test]
fn should_reject_invalid_udp_imei_at_wire_offset() {
    let mut invalid_length = bytes(UDP_CODEC8);
    invalid_length[7] = 14;
    assert!(matches!(
        decode_udp_datagram(&invalid_length),
        Err(UdpDecodeError::Invalid {
            offset: 6,
            reason: RejectionReason::InvalidImei,
        })
    ));

    let mut invalid_digit = bytes(UDP_CODEC8);
    invalid_digit[8] = b'x';
    assert!(matches!(
        decode_udp_datagram(&invalid_digit),
        Err(UdpDecodeError::Invalid {
            offset: 8,
            reason: RejectionReason::InvalidImei,
        })
    ));
}

#[test]
fn should_reject_declared_udp_datagram_above_configured_limit() {
    let input = bytes(UDP_CODEC8);
    let limit = UdpLimits::new(56).unwrap();
    assert_eq!(
        decode_udp_datagram_with_limits(&input, limit).unwrap_err(),
        UdpDecodeError::DatagramTooLarge {
            declared: input.len(),
            limit: 56,
        }
    );
}
