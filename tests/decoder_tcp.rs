#![cfg(feature = "alloc")]

mod common;

use std::num::NonZeroUsize;

use common::*;
use nom_teltonika::{decoder::*, encoder::*, protocol::*};

fn avl_packet(input: &[u8]) -> AvlPacketView<'_> {
    let mut rest = input;
    let FrameView::Avl(packet) = take_frame(&mut rest).unwrap() else {
        panic!("expected AVL")
    };
    assert!(rest.is_empty());
    packet
}

fn codec12_packet(input: &[u8]) -> GprsPacketView<'_> {
    let mut rest = input;
    let FrameView::Gprs(packet) = take_frame(&mut rest).unwrap() else {
        panic!("expected Codec 12")
    };
    assert!(rest.is_empty());
    packet
}

#[test]
fn should_decode_valid_imei_when_handshake_is_complete() {
    let input = bytes("000F333536333037303432343431303133");
    let mut rest = &input[..];
    assert_eq!(take_imei(&mut rest).unwrap().as_str(), "356307042441013");
    assert!(rest.is_empty());
}

#[test]
fn should_accept_a_declared_length_other_than_fifteen() {
    // The protocol only bounds the length to a `u16`; 15 is a real-world
    // IMEI convention, not something the framing enforces.
    let input = bytes("0005313233343500");
    let mut rest = &input[..];
    assert_eq!(take_imei(&mut rest).unwrap().as_str(), "12345");
    assert_eq!(rest, [0]);

    assert_eq!(ImeiView::try_from("123").unwrap().as_str(), "123");
    assert_eq!(
        ImeiView::try_from("1234567890é").unwrap_err(),
        ImeiError { index: 10 }
    );
}

#[test]
fn should_report_exact_need_when_imei_is_truncated() {
    let input = bytes("000F333536");
    let mut rest = &input[..];
    assert_eq!(
        take_imei(&mut rest).unwrap_err(),
        DecodeImeiError::Incomplete {
            needed: NonZeroUsize::new(12).unwrap()
        }
    );
    assert_eq!(rest, input);
}

#[test]
fn should_decode_all_supported_avl_codecs() {
    for (fixture, codec, count) in [
        (CODEC8, AvlCodec::Codec8, 1),
        (CODEC8_EXTENDED, AvlCodec::Codec8Extended, 1),
        (CODEC16, AvlCodec::Codec16, 2),
    ] {
        let input = bytes(fixture);
        let packet = avl_packet(&input);
        assert_eq!(packet.codec(), codec);
        assert_eq!(packet.records().len(), count);
    }
}

#[test]
fn should_preserve_values_as_sent_in_owned_result() {
    let input = bytes(CODEC8);
    let packet = avl_packet(&input).evaluate();
    let record = &packet.records()[0];
    assert_eq!(u64::from(record.timestamp()), 1_560_161_086_000);
    assert_eq!(record.gps().longitude_raw, 0);
    assert_eq!(record.io_elements().len(), 5);
}

#[test]
fn should_preserve_anomalous_coordinates_without_rejecting_frame() {
    let mut input = bytes(CODEC8);
    input[19..23].copy_from_slice(&i32::MAX.to_be_bytes());
    input[23..27].copy_from_slice(&i32::MIN.to_be_bytes());
    repair_crc(&mut input);
    let gps = avl_packet(&input).records().next().unwrap().gps();
    assert_eq!(gps.longitude_raw, i32::MAX);
    assert_eq!(gps.latitude_raw, i32::MIN);
    assert!(!gps.is_position_valid());
}

#[test]
fn should_return_incomplete_at_every_tcp_truncation_position() {
    for fixture in [CODEC8, CODEC8_EXTENDED, CODEC16, CODEC12_COMMAND] {
        let input = bytes(fixture);
        for end in 0..input.len() {
            let mut rest = &input[..end];
            assert!(matches!(
                take_frame(&mut rest),
                Err(DecodeFrameError::Incomplete { .. })
            ));
            assert_eq!(rest.len(), end);
        }
    }
}

#[test]
fn should_report_exact_need_at_each_tcp_framing_stage() {
    // The 8-byte header, then the declared total.
    let input = bytes(CODEC8);
    for (end, needed) in [
        (0, 8),
        (4, 4),
        (8, input.len() - 8),
        (9, input.len() - 9),
        (input.len() - 1, 1),
    ] {
        assert_eq!(
            take_frame(&mut &input[..end]).unwrap_err(),
            DecodeFrameError::Incomplete {
                needed: NonZeroUsize::new(needed).unwrap(),
            },
            "unexpected requirement after {end} byte(s)"
        );
    }
}

#[test]
fn should_consume_only_first_frame_when_frames_are_concatenated() {
    let first = bytes(CODEC8);
    let mut input = first.clone();
    input.extend_from_slice(&bytes(CODEC12_COMMAND)[..7]);
    let mut rest = &input[..];
    take_frame(&mut rest).unwrap();
    assert_eq!(rest, &input[first.len()..]);
}

#[test]
fn should_preserve_variable_codec8_extended_io_bytes_in_owned_value() {
    let mut data = vec![0x8e, 1];
    data.extend_from_slice(&[0; 8]);
    data.push(0);
    data.extend_from_slice(&[0; 15]);
    data.extend_from_slice(&0u16.to_be_bytes());
    // N counts the variable-length element too: N1 + N2 + N4 + N8 + NX.
    data.extend_from_slice(&1u16.to_be_bytes());
    for _ in 0..4 {
        data.extend_from_slice(&0u16.to_be_bytes());
    }
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0x1234u16.to_be_bytes());
    data.extend_from_slice(&3u16.to_be_bytes());
    data.extend_from_slice(&[0xff, 0, 0x80]);
    data.push(1);

    let input = tcp_frame_from_data(&data);
    let packet = avl_packet(&input).evaluate();
    assert_eq!(
        packet.records()[0].io_elements()[0].value(),
        &IoValue::Bytes(vec![0xff, 0, 0x80])
    );
}

#[test]
fn should_decode_codec12_binary_batch_and_response() {
    let binary = [0xff, 0x00, 0x80];
    let batch = encode_gprs_frame(
        GprsMessageType::Command,
        &[binary.as_slice(), b"getinfo".as_slice()],
    )
    .unwrap();
    let messages: Vec<_> = codec12_packet(&batch).messages().collect();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].kind(), GprsMessageType::Command);
    assert_eq!(messages[0].payload(), binary);
    assert_eq!(messages[1].payload(), b"getinfo");

    let mut response = encode_gprs_frame(GprsMessageType::Command, &[b"ok"]).unwrap();
    response[10] = 0x06;
    repair_crc(&mut response);
    let message = codec12_packet(&response).messages().next().unwrap();
    assert_eq!(message.kind(), GprsMessageType::Response);
}

#[test]
fn should_read_the_messages_the_first_codec12_quantity_declares() {
    let batch = encode_gprs_frame(
        GprsMessageType::Command,
        &[b"one".as_slice(), b"two".as_slice()],
    )
    .unwrap();
    let payloads: Vec<_> = codec12_packet(&batch)
        .messages()
        .map(|message| message.payload())
        .collect();
    assert_eq!(payloads, [b"one", b"two"]);

    // The value of the second quantity is not read.
    let mut mismatched = batch.clone();
    let trailing_count = mismatched.len() - 5;
    mismatched[trailing_count] = 7;
    repair_crc(&mut mismatched);
    assert_eq!(codec12_packet(&mismatched).messages().len(), 2);

    // A first quantity under the messages held leaves bytes after them.
    let mut fewer = batch;
    fewer[9] = 1;
    repair_crc(&mut fewer);
    assert_eq!(
        invalid_frame(&fewer),
        FrameError::Gprs(GprsPacketError::TrailingBytes)
    );
}

#[test]
fn should_validate_codec12_encoder_inputs_without_panicking() {
    let none: [&[u8]; 0] = [];
    assert_eq!(
        encode_gprs_frame(GprsMessageType::Command, &none),
        Err(EncodeGprsError::NoMessages)
    );
    let commands = vec![b"x".as_slice(); 256];
    assert_eq!(
        encode_gprs_frame(GprsMessageType::Command, &commands),
        Err(EncodeGprsError::TooManyMessages {
            count: 256,
            limit: 255,
        })
    );
}

#[test]
fn should_match_official_codec12_encoder_example() {
    assert_eq!(
        encode_gprs_frame(GprsMessageType::Command, &[b"getinfo"]).unwrap(),
        bytes(CODEC12_COMMAND)
    );
}

/// Decodes a complete frame expected to be invalid, checking that `input` is
/// advanced past it.
fn invalid_frame(input: &[u8]) -> FrameError {
    let mut rest = input;
    let Err(DecodeFrameError::InvalidFrame { len, reason }) = take_frame(&mut rest) else {
        panic!("expected an invalid frame")
    };
    assert!(rest.is_empty(), "an invalid frame must be consumed");
    assert_eq!(len, input.len(), "the error reports the frame's length");
    reason
}

#[test]
fn should_reject_imei_when_content_is_not_ascii() {
    // 0x3A would be an ASCII ':' — use a genuinely non-ASCII byte (0xE9)
    // since digit-only content is no longer enforced by take_imei.
    let input = bytes("000F3335363330373034323434313031E9");
    let mut rest = &input[..];
    assert_eq!(
        take_imei(&mut rest).unwrap_err(),
        DecodeImeiError::NotAscii(ImeiError { index: 14 })
    );
    assert!(rest.is_empty());
}

#[test]
fn should_reject_and_consume_delimited_crc_mismatch() {
    let mut input = bytes(CODEC8);
    let total = input.len();
    input[total - 1] ^= 1;
    assert!(matches!(
        invalid_frame(&input),
        FrameError::CrcMismatch { .. }
    ));
}

#[test]
fn should_reject_avl_duplicate_count_mismatch() {
    let mut input = bytes(CODEC8);
    let second_count = input.len() - 5;
    input[second_count] = 2;
    repair_crc(&mut input);
    assert_eq!(
        invalid_frame(&input),
        FrameError::Avl(AvlPacketError::RecordCountMismatch {
            first: 1,
            second: 2
        })
    );
}

#[test]
fn should_reject_invalid_priority_generation_and_io_count() {
    let mut priority = bytes(CODEC8);
    priority[18] = 3;
    repair_crc(&mut priority);
    assert_eq!(
        invalid_frame(&priority),
        FrameError::Avl(AvlPacketError::InvalidPriority(3))
    );

    let mut generation = bytes(CODEC16);
    generation[36] = 9;
    repair_crc(&mut generation);
    assert_eq!(
        invalid_frame(&generation),
        FrameError::Avl(AvlPacketError::InvalidGenerationType(9))
    );

    let mut io_count = bytes(CODEC8);
    io_count[35] = 6;
    repair_crc(&mut io_count);
    assert_eq!(
        invalid_frame(&io_count),
        FrameError::Avl(AvlPacketError::IoCountMismatch {
            declared: 6,
            counted: 5
        })
    );
}

#[test]
fn should_fail_immediately_when_declared_frame_exceeds_limit() {
    let mut header = vec![0; 9];
    header[4..8].copy_from_slice(&10_000u32.to_be_bytes());
    header[8] = 0x08;
    let mut rest = &header[..];
    assert!(matches!(
        take_frame(&mut rest),
        Err(DecodeFrameError::InvalidHeader(HeaderError::TooLong {
            declared: 10_012,
            limit: 1280
        }))
    ));
    assert_eq!(rest, header);
}

#[test]
fn should_treat_untrusted_preamble_as_fatal() {
    let mut input = bytes(CODEC8);
    input[0] = 1;
    let mut rest = &input[..];
    assert_eq!(
        take_frame(&mut rest).unwrap_err(),
        DecodeFrameError::InvalidHeader(HeaderError::InvalidPreamble {
            found: [1, 0, 0, 0]
        })
    );
    assert_eq!(rest, input);
}

#[test]
fn should_reject_codec12_messages_of_unknown_type() {
    // The wiki allows only 0x05 and 0x06 ("Codec 12 > General Codec12
    // message structure"); v0.2.0 kept other types as device-specific.
    let batch = encode_gprs_frame(
        GprsMessageType::Command,
        &[b"one".as_slice(), b"two".as_slice()],
    )
    .unwrap();
    let mut other = batch;
    other[10] = 0x7f;
    repair_crc(&mut other);
    assert_eq!(
        invalid_frame(&other),
        FrameError::Gprs(GprsPacketError::InvalidMessageType(0x7f))
    );
}

#[test]
fn should_handle_specific_codec12_batch_cases() {
    let empty = tcp_frame_from_data(&[0x0c, 0, 0]);
    assert_eq!(
        invalid_frame(&empty),
        FrameError::Gprs(GprsPacketError::NoMessages)
    );

    // Mixed types are accepted: each message carries its own type.
    let mut mixed = encode_gprs_frame(
        GprsMessageType::Command,
        &[b"one".as_slice(), b"two".as_slice()],
    )
    .unwrap();
    mixed[18] = 0x06;
    repair_crc(&mut mixed);
    let types: Vec<_> = codec12_packet(&mixed)
        .messages()
        .map(|message| message.kind())
        .collect();
    assert_eq!(types, [GprsMessageType::Command, GprsMessageType::Response]);

    // The first quantity is one byte: 255 messages at most.
    let mut data = vec![0x0c, u8::MAX];
    for _ in 0..u8::MAX {
        data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
    }
    data.push(u8::MAX);
    let input = tcp_frame_from_data(&data);
    assert_eq!(codec12_packet(&input).messages().len(), 255);
}

#[test]
fn should_reject_truncated_bounded_payload() {
    let mut input = encode_gprs_frame(GprsMessageType::Command, &[b"getinfo"]).unwrap();
    input[11..15].copy_from_slice(&100u32.to_be_bytes());
    repair_crc(&mut input);
    assert_eq!(
        invalid_frame(&input),
        FrameError::Gprs(GprsPacketError::Truncated)
    );
}

#[test]
fn should_reject_empty_avl_packet_with_specific_reason() {
    let empty = tcp_frame_from_data(&[0x08, 0, 0]);
    assert_eq!(
        invalid_frame(&empty),
        FrameError::Avl(AvlPacketError::NoRecords)
    );
}
