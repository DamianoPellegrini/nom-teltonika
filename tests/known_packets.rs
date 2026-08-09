mod common;

use common::*;
use nom_teltonika::{
    decoder::{DecodeError, RejectionReason, decode_tcp_frame},
    encoder::encode_codec12_command,
    protocol::{Codec12Message, Frame},
};

#[test]
fn decodes_the_original_c8example1_reference_packet() {
    // tests/c8example1.bin (the packet this suite was originally built from,
    // gitignored and not tracked) is byte-identical to this hex fixture —
    // see the doc comment on `CODEC8` in tests/common/mod.rs.
    let input = bytes(CODEC8);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Avl(packet) = decoded.value else {
        panic!("expected AVL frame")
    };
    assert_eq!(packet.records().len(), 1);
}

#[test]
fn decodes_codec8_single_record_alt_example() {
    let input = bytes(CODEC8_SINGLE_RECORD_ALT);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Avl(packet) = decoded.value else {
        panic!("expected AVL frame")
    };
    assert_eq!(packet.records().len(), 1);
}

#[test]
fn decodes_codec8_two_record_example() {
    let input = bytes(CODEC8_TWO_RECORDS);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Avl(packet) = decoded.value else {
        panic!("expected AVL frame")
    };
    assert_eq!(packet.records().len(), 2);
}

#[test]
fn decodes_codec8_extended_example() {
    let input = bytes(CODEC8_EXTENDED);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Avl(packet) = decoded.value else {
        panic!("expected AVL frame")
    };
    assert_eq!(packet.records().len(), 1);
}

#[test]
fn decodes_codec16_example() {
    let input = bytes(CODEC16);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Avl(packet) = decoded.value else {
        panic!("expected AVL frame")
    };
    assert_eq!(packet.records().len(), 2);
}

#[test]
fn decodes_codec12_getinfo_command() {
    let input = bytes(CODEC12_COMMAND);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Codec12(packet) = decoded.value else {
        panic!("expected Codec 12 frame")
    };
    assert!(matches!(
        packet.message(),
        Codec12Message::Command(payloads) if payloads[0].as_slice() == b"getinfo".as_slice()
    ));
}

#[test]
fn decodes_codec12_getio_command() {
    let input = bytes(CODEC12_GETIO_COMMAND);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Codec12(packet) = decoded.value else {
        panic!("expected Codec 12 frame")
    };
    assert!(matches!(
        packet.message(),
        Codec12Message::Command(payloads) if payloads[0].as_slice() == b"getio".as_slice()
    ));
}

#[test]
fn decodes_codec12_getinfo_response() {
    let input = bytes(CODEC12_GETINFO_RESPONSE);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Codec12(packet) = decoded.value else {
        panic!("expected Codec 12 frame")
    };
    let expected: &[u8] = b"INI:2019/7/22 7:22 RTC:2019/7/22 7:53 RST:2 ERR:1 SR:0 BR:0 CF:0 FG:0 FL:0 TU:0/0 UT:0 SMS:0 NOGPS:0:30 GPS:1 SAT:0 RS:3 RF:65 SF:1 MD:0";
    assert!(matches!(
        packet.message(),
        Codec12Message::Response(payloads) if payloads[0].as_slice() == expected
    ));
}

#[test]
fn decodes_codec12_getio_response() {
    let input = bytes(CODEC12_GETIO_RESPONSE);
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Codec12(packet) = decoded.value else {
        panic!("expected Codec 12 frame")
    };
    let expected: &[u8] = b"DI1:1 DI2:0 DI3:0 AIN1:0 AIN2:16924 DO1:0 DO2:1";
    assert!(matches!(
        packet.message(),
        Codec12Message::Response(payloads) if payloads[0].as_slice() == expected
    ));
}

#[test]
fn decodes_real_simulator_medisail_command() {
    let input = encode_codec12_command(MEDISAIL_COMMAND_TEXT.as_bytes()).unwrap();
    let decoded = decode_tcp_frame(&input).unwrap();
    assert_eq!(decoded.consumed, input.len());
    let Frame::Codec12(packet) = decoded.value else {
        panic!("expected Codec 12 frame")
    };
    assert!(matches!(
        packet.message(),
        Codec12Message::Command(payloads) if payloads[0].as_slice() == MEDISAIL_COMMAND_TEXT.as_bytes()
    ));
}

#[test]
fn rejects_corrupted_codec8_two_record_example() {
    let mut input = bytes(CODEC8_TWO_RECORDS);
    let last = input.len() - 1;
    input[last] ^= 1;
    assert!(matches!(
        decode_tcp_frame(&input),
        Err(DecodeError::Rejected {
            reason: RejectionReason::CrcMismatch { .. },
            ..
        })
    ));
}

#[test]
fn rejects_corrupted_codec8_extended_example() {
    let mut input = bytes(CODEC8_EXTENDED);
    let last = input.len() - 1;
    input[last] ^= 1;
    assert!(matches!(
        decode_tcp_frame(&input),
        Err(DecodeError::Rejected {
            reason: RejectionReason::CrcMismatch { .. },
            ..
        })
    ));
}

#[test]
fn rejects_corrupted_codec16_example() {
    let mut input = bytes(CODEC16);
    let last = input.len() - 1;
    input[last] ^= 1;
    assert!(matches!(
        decode_tcp_frame(&input),
        Err(DecodeError::Rejected {
            reason: RejectionReason::CrcMismatch { .. },
            ..
        })
    ));
}

#[test]
fn rejects_corrupted_codec12_getinfo_response() {
    let mut input = bytes(CODEC12_GETINFO_RESPONSE);
    let last = input.len() - 1;
    input[last] ^= 1;
    assert!(matches!(
        decode_tcp_frame(&input),
        Err(DecodeError::Rejected {
            reason: RejectionReason::CrcMismatch { .. },
            ..
        })
    ));
}
