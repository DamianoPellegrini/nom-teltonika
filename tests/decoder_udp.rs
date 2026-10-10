#![cfg(feature = "alloc")]

mod common;

use common::*;
use nom_teltonika::{decoder::*, encoder::encode_udp_ack};

#[test]
fn should_decode_official_udp_datagram_and_encode_correlated_ack() {
    let input = bytes(UDP_CODEC8);
    let mut rest = &input[..];
    let datagram = take_datagram(&mut rest).unwrap();
    assert!(rest.is_empty());
    assert_eq!(datagram.packet_id(), 0xcafe);
    assert_eq!(datagram.avl_packet_id(), 5);
    assert_eq!(datagram.imei().as_str(), "352093086403655");
    // "Codec 8 > Codec8 protocol sending over UDP > Example": the server
    // responds `0005CAFE010501`.
    assert_eq!(
        encode_udp_ack(datagram.ids(), 1),
        [0, 5, 0xca, 0xfe, 1, 5, 1]
    );
}

/// Decodes a datagram expected to be rejected, checking that `input` is
/// left untouched.
fn error(input: &[u8]) -> DatagramError {
    let mut rest = input;
    let error = take_datagram(&mut rest).unwrap_err();
    assert_eq!(rest, input);
    let DecodeDatagramError::InvalidDatagram { ids, reason } = error else {
        panic!("expected a datagram with a header")
    };
    // The IDs of the official example, to answer it with.
    assert_eq!(encode_udp_ack(ids, 0), [0, 5, 0xca, 0xfe, 1, 5, 0]);
    reason
}

#[test]
fn should_distinguish_short_header_from_length_mismatch() {
    for short in [&[][..], &[0], &[0, 0x3d, 0xca, 0xfe, 1]] {
        assert_eq!(
            take_datagram(&mut &short[..]).unwrap_err(),
            DecodeDatagramError::NoHeader
        );
    }

    // The length field excludes itself.
    let input = bytes(UDP_CODEC8);
    let declared = u16::try_from(input.len() - 2).unwrap();
    assert_eq!(
        error(&input[..input.len() - 1]),
        DatagramError::LengthMismatch {
            declared,
            actual: input.len() - 3,
        }
    );
    let mut trailing = input.clone();
    trailing.push(0);
    assert_eq!(
        error(&trailing),
        DatagramError::LengthMismatch {
            declared,
            actual: input.len() - 1,
        }
    );
}

#[test]
fn should_honor_the_declared_udp_imei_length() {
    // The IMEI follows the TCP rule: any declared length up to 128 bytes,
    // ASCII only. v0.2.0 required 15 digits.
    let mut shorter = bytes(UDP_CODEC8);
    shorter[7] = 14;
    // The 15th digit, '5', is now read as the codec ID.
    assert_eq!(error(&shorter), DatagramError::UnsupportedCodec(b'5'));

    let mut letter = bytes(UDP_CODEC8);
    letter[8] = b'x';
    let mut rest = &letter[..];
    assert_eq!(
        take_datagram(&mut rest).unwrap().imei().as_str(),
        "x52093086403655"
    );

    let mut not_ascii = bytes(UDP_CODEC8);
    not_ascii[8] = 0xe9;
    assert_eq!(
        error(&not_ascii),
        DatagramError::ImeiNotAscii(nom_teltonika::protocol::ImeiError { index: 0 })
    );
}
