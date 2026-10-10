#![cfg(feature = "alloc")]

mod common;

use common::strategies::{
    AvlRecordRecipe, DatagramRecipe, avl_packet, build_avl_data, build_datagram, build_gprs_frame,
    datagram_recipe, frame, gprs_messages,
};
use common::tcp_frame_from_data;
use nom_teltonika::{
    decoder::{
        DecodeFrameError, DecodeImeiError, FrameError, HeaderError, take_datagram, take_frame,
        take_imei,
    },
    encoder::{AvlRecordFields, DatagramHeaderFields, encode_avl_datagram, encode_avl_frame},
    protocol::{
        AvlCodec, AvlPacket, AvlRecord, AvlTimestamp, Codec, Frame, GenerationType, GpsElement,
        ImeiView, IoId, IoValue, Priority,
    },
};
use proptest::prelude::*;

/// Asserts `record` holds exactly what `recipe` specified, accounting for the
/// per-codec truncations `encode_record` applies (1-byte event id and IO
/// ids for Codec8; no generation type outside Codec16; no extended-bytes IO
/// group outside Codec8 Extended).
fn assert_record_matches(record: &AvlRecord, recipe: &AvlRecordRecipe, codec: AvlCodec) {
    assert_eq!(u64::from(record.timestamp()), recipe.timestamp);

    let expected_priority = match recipe.priority {
        0 => Priority::Low,
        1 => Priority::High,
        2 => Priority::Panic,
        other => panic!("strategy generated invalid priority {other}"),
    };
    assert_eq!(record.priority(), expected_priority);

    assert_eq!(record.gps().longitude_raw, recipe.longitude);
    assert_eq!(record.gps().latitude_raw, recipe.latitude);
    assert_eq!(record.gps().altitude_meters, recipe.altitude);
    assert_eq!(record.gps().angle_degrees, recipe.angle);
    assert_eq!(record.gps().satellites, recipe.satellites);
    assert_eq!(record.gps().speed_kph, recipe.speed);

    let expected_event_id = if codec == AvlCodec::Codec8 {
        u16::from(recipe.event_id as u8)
    } else {
        recipe.event_id
    };
    let expected_event = (expected_event_id != 0).then(|| IoId::from(expected_event_id));
    assert_eq!(record.event_io_id(), expected_event);

    if codec == AvlCodec::Codec16 {
        let expected_generation = match recipe.generation_type {
            0 => GenerationType::OnExit,
            1 => GenerationType::OnEntrance,
            2 => GenerationType::OnBoth,
            3 => GenerationType::Reserved,
            4 => GenerationType::Hysteresis,
            5 => GenerationType::OnChange,
            6 => GenerationType::Eventual,
            7 => GenerationType::Periodical,
            other => panic!("strategy generated invalid generation type {other}"),
        };
        assert_eq!(record.generation_type(), Some(expected_generation));
    } else {
        assert_eq!(record.generation_type(), None);
    }

    let id_of = |id: u16| -> IoId {
        if codec == AvlCodec::Codec8 {
            IoId::from(u16::from(id as u8))
        } else {
            IoId::from(id)
        }
    };

    let mut expected = Vec::new();
    for (id, value) in &recipe.io_u8 {
        expected.push((id_of(*id), IoValue::U8(*value)));
    }
    for (id, value) in &recipe.io_u16 {
        expected.push((id_of(*id), IoValue::U16(*value)));
    }
    for (id, value) in &recipe.io_u32 {
        expected.push((id_of(*id), IoValue::U32(*value)));
    }
    for (id, value) in &recipe.io_u64 {
        expected.push((id_of(*id), IoValue::U64(*value)));
    }
    if codec == AvlCodec::Codec8Extended {
        for (id, value) in &recipe.io_bytes {
            expected.push((IoId::from(*id), IoValue::Bytes(value.clone())));
        }
    }

    let actual: Vec<(IoId, IoValue)> = record
        .io_elements()
        .iter()
        .map(|element| (element.id(), element.value().clone()))
        .collect();
    assert_eq!(actual, expected);
}

/// Asserts `packet` holds exactly the records of `recipes`, in order.
fn assert_packet_matches(packet: &AvlPacket, recipes: &[AvlRecordRecipe], codec: AvlCodec) {
    assert_eq!(packet.codec(), codec);
    assert_eq!(packet.records().len(), recipes.len());
    for (record, recipe) in packet.records().iter().zip(recipes) {
        assert_record_matches(record, recipe, codec);
    }
}

// The strategies' encoders are written independently from the library's,
// from the wiki layouts. The codec is drawn with each case: a property that
// holds for one codec's field widths must hold for all three.
proptest! {
    #[test]
    fn avl_frames_decode_to_their_recipe((codec, recipes) in avl_packet()) {
        let bytes = tcp_frame_from_data(&build_avl_data(codec, &recipes));
        let mut rest = &bytes[..];
        let decoded = take_frame(&mut rest).expect("frame built by the strategy must be valid");
        prop_assert!(rest.is_empty());
        let Frame::Avl(packet) = Frame::from(decoded) else {
            panic!("expected AVL frame")
        };
        assert_packet_matches(&packet, &recipes, codec);
    }

    #[test]
    fn datagrams_decode_to_their_recipe(
        (codec, recipes) in avl_packet(),
        header in datagram_recipe(),
    ) {
        let bytes = build_datagram(&header, &build_avl_data(codec, &recipes));
        let mut rest = &bytes[..];
        let datagram = take_datagram(&mut rest)
            .expect("datagram built by the strategy must be valid")
            .evaluate();
        prop_assert!(rest.is_empty());
        prop_assert_eq!(datagram.packet_id(), header.packet_id);
        prop_assert_eq!(datagram.avl_packet_id(), header.avl_packet_id);
        prop_assert_eq!(datagram.imei().as_str(), &header.imei);
        assert_packet_matches(datagram.packet(), &recipes, codec);
    }

    #[test]
    fn gprs_frames_decode_to_their_messages(messages in gprs_messages()) {
        let bytes = build_gprs_frame(&messages);
        let mut rest = &bytes[..];
        let decoded = take_frame(&mut rest).expect("frame built by the strategy must be valid");
        prop_assert!(rest.is_empty());
        let Frame::Gprs(packet) = Frame::from(decoded) else {
            panic!("expected Codec 12 frame")
        };
        let payloads: Vec<&[u8]> = packet.messages().iter().map(|message| message.payload()).collect();
        prop_assert_eq!(payloads, messages);
    }

    #[test]
    fn library_encoders_match_the_reference(
        (codec, recipes) in avl_packet(),
        header in datagram_recipe(),
    ) {
        let data = build_avl_data(codec, &recipes);
        let (frame, datagram) = encode_with_library(codec, &recipes, &header);
        prop_assert_eq!(frame, tcp_frame_from_data(&data));
        prop_assert_eq!(datagram, build_datagram(&header, &data));
    }

    // CRC-16 detects every change confined to 16 bits, so one changed byte
    // has one expected outcome, set by the field it is in. Only a changed
    // length has several, since it moves the end of the frame.
    #[test]
    fn a_changed_byte_is_reported_by_the_field_it_is_in(
        mut bytes in frame(),
        index in any::<prop::sample::Index>(),
        change in 1..=u8::MAX,
    ) {
        let index = index.index(bytes.len());
        bytes[index] ^= change;
        let mut rest = &bytes[..];
        let result = take_frame(&mut rest);
        let consumed = bytes.len() - rest.len();
        match index {
            0..4 => {
                let found = [bytes[0], bytes[1], bytes[2], bytes[3]];
                prop_assert_eq!(
                    result.unwrap_err(),
                    DecodeFrameError::InvalidHeader(HeaderError::InvalidPreamble { found })
                );
                prop_assert_eq!(consumed, 0);
            }
            4..8 => match result {
                // Delimited by the changed length, wherever that ends.
                Ok(_) => prop_assert!(consumed > 0),
                Err(DecodeFrameError::InvalidFrame { len, .. }) => prop_assert_eq!(consumed, len),
                Err(DecodeFrameError::Incomplete { .. } | DecodeFrameError::InvalidHeader(_)) => {
                    prop_assert_eq!(consumed, 0);
                }
            },
            _ => {
                let Err(DecodeFrameError::InvalidFrame { len, reason }) = result else {
                    panic!("expected an invalid frame, got {result:?}")
                };
                prop_assert_eq!(len, bytes.len());
                prop_assert_eq!(consumed, len);
                // A codec ID that is no longer supported is told before the
                // CRC is computed.
                match Codec::try_from(bytes[8]) {
                    Err(codec_id) => prop_assert_eq!(reason, FrameError::UnsupportedCodec(codec_id)),
                    Ok(_) => prop_assert!(
                        matches!(reason, FrameError::CrcMismatch { .. }),
                        "{:?}", reason
                    ),
                }
            }
        }
    }

    // No outcome is expected of arbitrary bytes: decoding must not panic,
    // and must leave the cursor untouched unless a unit was delimited.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=64)) {
        // A valid preamble and a small length make it past the header.
        let mut framed = vec![0, 0, 0, 0, 0, 0, 0, bytes.len().min(52) as u8];
        framed.extend_from_slice(&bytes);
        for input in [&bytes[..], &framed[..]] {
            let mut rest = input;
            if let Err(DecodeFrameError::Incomplete { .. } | DecodeFrameError::InvalidHeader(_)) =
                take_frame(&mut rest)
            {
                prop_assert_eq!(rest, input);
            }

            let mut rest = input;
            if take_datagram(&mut rest).is_err() {
                prop_assert_eq!(rest, input);
            }

            let mut rest = input;
            if let Err(DecodeImeiError::Incomplete { .. }) = take_imei(&mut rest) {
                prop_assert_eq!(rest, input);
            }
        }
    }
}

/// The IO elements of a recipe, as the library encoder takes them.
struct RecipeIo {
    io_u8: Vec<(IoId, u8)>,
    io_u16: Vec<(IoId, u16)>,
    io_u32: Vec<(IoId, u32)>,
    io_u64: Vec<(IoId, u64)>,
    io_bytes: Vec<(IoId, Vec<u8>)>,
}

/// Returns the ID the strategy's encoder writes for `id` in `codec`:
/// Codec 8 IDs are one byte.
fn sent_id(codec: AvlCodec, id: u16) -> IoId {
    IoId::from(if codec == AvlCodec::Codec8 {
        id & 0xff
    } else {
        id
    })
}

fn recipe_io(recipe: &AvlRecordRecipe, codec: AvlCodec) -> RecipeIo {
    fn convert<T: Copy>(codec: AvlCodec, elements: &[(u16, T)]) -> Vec<(IoId, T)> {
        elements
            .iter()
            .map(|&(id, value)| (sent_id(codec, id), value))
            .collect()
    }
    RecipeIo {
        io_u8: convert(codec, &recipe.io_u8),
        io_u16: convert(codec, &recipe.io_u16),
        io_u32: convert(codec, &recipe.io_u32),
        io_u64: convert(codec, &recipe.io_u64),
        io_bytes: recipe
            .io_bytes
            .iter()
            .map(|(id, value)| (IoId::from(*id), value.clone()))
            .collect(),
    }
}

/// Encodes `recipes` into a frame and a datagram with the library encoders,
/// reading each field as the strategy's own encoder writes it for `codec`.
fn encode_with_library(
    codec: AvlCodec,
    recipes: &[AvlRecordRecipe],
    header: &DatagramRecipe,
) -> (Vec<u8>, Vec<u8>) {
    let ios: Vec<RecipeIo> = recipes
        .iter()
        .map(|recipe| recipe_io(recipe, codec))
        .collect();
    let bytes: Vec<Vec<(IoId, &[u8])>> = ios
        .iter()
        .map(|io| {
            io.io_bytes
                .iter()
                .map(|(id, value)| (*id, &value[..]))
                .collect()
        })
        .collect();
    let records: Vec<AvlRecordFields<'_>> = recipes
        .iter()
        .zip(&ios)
        .zip(&bytes)
        .map(|((recipe, io), io_bytes)| {
            let gps = GpsElement {
                longitude_raw: recipe.longitude,
                latitude_raw: recipe.latitude,
                altitude_meters: recipe.altitude,
                angle_degrees: recipe.angle,
                satellites: recipe.satellites,
                speed_kph: recipe.speed,
            };
            let priority = Priority::try_from(recipe.priority).unwrap();
            let mut record =
                AvlRecordFields::new(AvlTimestamp::from(recipe.timestamp), priority, gps)
                    .with_io_u8(&io.io_u8)
                    .with_io_u16(&io.io_u16)
                    .with_io_u32(&io.io_u32)
                    .with_io_u64(&io.io_u64);
            let event_io_id = sent_id(codec, recipe.event_id);
            if u16::from(event_io_id) != 0 {
                record = record.with_event_io_id(event_io_id);
            }
            if codec == AvlCodec::Codec16 {
                let generation_type = GenerationType::try_from(recipe.generation_type).unwrap();
                record = record.with_generation_type(generation_type);
            }
            if codec == AvlCodec::Codec8Extended {
                record = record.with_io_bytes(io_bytes);
            }
            record
        })
        .collect();
    let header = DatagramHeaderFields {
        packet_id: header.packet_id,
        avl_packet_id: header.avl_packet_id,
        imei: ImeiView::try_from(&header.imei[..]).unwrap(),
    };
    (
        encode_avl_frame(codec, &records).expect("strategy records fit their codec"),
        encode_avl_datagram(header, codec, &records).expect("strategy records fit a datagram"),
    )
}
