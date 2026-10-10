#![cfg(feature = "alloc")]

mod common;

use common::*;
use nom_teltonika::{
    decoder::{DecodeFrameError, FrameError, take_frame},
    encoder::encode_gprs_frame,
    protocol::{AvlPacketView, FrameView, GprsMessageType, GprsPacketView},
};

fn avl_packet(input: &[u8]) -> AvlPacketView<'_> {
    let mut rest = input;
    let FrameView::Avl(packet) = take_frame(&mut rest).unwrap() else {
        panic!("expected AVL frame")
    };
    assert!(rest.is_empty());
    packet
}

fn codec12_packet(input: &[u8]) -> GprsPacketView<'_> {
    let mut rest = input;
    let FrameView::Gprs(packet) = take_frame(&mut rest).unwrap() else {
        panic!("expected Codec 12 frame")
    };
    assert!(rest.is_empty());
    packet
}

fn single_message(packet: GprsPacketView<'_>) -> (GprsMessageType, &[u8]) {
    let mut messages = packet.messages();
    assert_eq!(messages.len(), 1);
    let message = messages.next().unwrap();
    (message.kind(), message.payload())
}

#[test]
fn decodes_the_original_c8example1_reference_packet() {
    // tests/c8example1.bin (the packet this suite was originally built from,
    // gitignored and not tracked) is byte-identical to this hex fixture —
    // see the doc comment on `CODEC8` in tests/common/mod.rs.
    let input = bytes(CODEC8);
    assert_eq!(avl_packet(&input).records().len(), 1);
}

#[test]
fn decodes_codec8_single_record_alt_example() {
    let input = bytes(CODEC8_SINGLE_RECORD_ALT);
    assert_eq!(avl_packet(&input).records().len(), 1);
}

#[test]
fn decodes_codec8_two_record_example() {
    let input = bytes(CODEC8_TWO_RECORDS);
    assert_eq!(avl_packet(&input).records().len(), 2);
}

#[test]
fn decodes_codec8_extended_example() {
    let input = bytes(CODEC8_EXTENDED);
    assert_eq!(avl_packet(&input).records().len(), 1);
}

#[test]
fn decodes_codec16_example() {
    let input = bytes(CODEC16);
    assert_eq!(avl_packet(&input).records().len(), 2);
}

#[test]
fn decodes_codec12_getinfo_command() {
    let input = bytes(CODEC12_COMMAND);
    assert_eq!(
        single_message(codec12_packet(&input)),
        (GprsMessageType::Command, &b"getinfo"[..])
    );
}

#[test]
fn decodes_codec12_getio_command() {
    let input = bytes(CODEC12_GETIO_COMMAND);
    assert_eq!(
        single_message(codec12_packet(&input)),
        (GprsMessageType::Command, &b"getio"[..])
    );
}

#[test]
fn decodes_codec12_getinfo_response() {
    let input = bytes(CODEC12_GETINFO_RESPONSE);
    let expected: &[u8] = b"INI:2019/7/22 7:22 RTC:2019/7/22 7:53 RST:2 ERR:1 SR:0 BR:0 CF:0 FG:0 FL:0 TU:0/0 UT:0 SMS:0 NOGPS:0:30 GPS:1 SAT:0 RS:3 RF:65 SF:1 MD:0";
    assert_eq!(
        single_message(codec12_packet(&input)),
        (GprsMessageType::Response, expected)
    );
}

#[test]
fn decodes_codec12_getio_response() {
    let input = bytes(CODEC12_GETIO_RESPONSE);
    let expected: &[u8] = b"DI1:1 DI2:0 DI3:0 AIN1:0 AIN2:16924 DO1:0 DO2:1";
    assert_eq!(
        single_message(codec12_packet(&input)),
        (GprsMessageType::Response, expected)
    );
}

#[test]
fn decodes_real_simulator_medisail_command() {
    let input = encode_gprs_frame(
        GprsMessageType::Command,
        &[MEDISAIL_COMMAND_TEXT.as_bytes()],
    )
    .unwrap();
    assert_eq!(
        single_message(codec12_packet(&input)),
        (GprsMessageType::Command, MEDISAIL_COMMAND_TEXT.as_bytes())
    );
}

#[test]
fn rejects_corrupted_codec8_two_record_example() {
    let mut input = bytes(CODEC8_TWO_RECORDS);
    let last = input.len() - 1;
    input[last] ^= 1;
    let mut rest = &input[..];
    assert!(matches!(
        take_frame(&mut rest),
        Err(DecodeFrameError::InvalidFrame {
            reason: FrameError::CrcMismatch { .. },
            ..
        })
    ));
    assert!(rest.is_empty());
}

#[test]
fn rejects_corrupted_codec8_extended_example() {
    let mut input = bytes(CODEC8_EXTENDED);
    let last = input.len() - 1;
    input[last] ^= 1;
    let mut rest = &input[..];
    assert!(matches!(
        take_frame(&mut rest),
        Err(DecodeFrameError::InvalidFrame {
            reason: FrameError::CrcMismatch { .. },
            ..
        })
    ));
    assert!(rest.is_empty());
}

#[test]
fn rejects_corrupted_codec16_example() {
    let mut input = bytes(CODEC16);
    let last = input.len() - 1;
    input[last] ^= 1;
    let mut rest = &input[..];
    assert!(matches!(
        take_frame(&mut rest),
        Err(DecodeFrameError::InvalidFrame {
            reason: FrameError::CrcMismatch { .. },
            ..
        })
    ));
    assert!(rest.is_empty());
}

#[test]
fn rejects_corrupted_codec12_getinfo_response() {
    let mut input = bytes(CODEC12_GETINFO_RESPONSE);
    let last = input.len() - 1;
    input[last] ^= 1;
    let mut rest = &input[..];
    assert!(matches!(
        take_frame(&mut rest),
        Err(DecodeFrameError::InvalidFrame {
            reason: FrameError::CrcMismatch { .. },
            ..
        })
    ));
    assert!(rest.is_empty());
}
