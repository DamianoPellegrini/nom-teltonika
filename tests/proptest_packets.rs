#![cfg(feature = "alloc")]

mod common;

use common::strategies::{
    AvlRecordRecipe, avl_frame, avl_frame_with_corruption, codec12_frame,
    codec12_frame_with_corruption,
};
use nom_teltonika::{
    decoder::{DecodeFrameError, DecodeImeiError, take_datagram, take_frame, take_imei},
    encoder::{AvlRecordFields, encode_avl_frame},
    protocol::{
        AvlCodec, AvlRecord, AvlTimestamp, Frame, GenerationType, GpsElement, IoId, IoValue,
        Priority,
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

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn codec8_frame_round_trips((bytes, recipes) in avl_frame(AvlCodec::Codec8)) {
        let mut rest = &bytes[..];
        let decoded = take_frame(&mut rest).expect("frame built by the strategy must be valid");
        prop_assert!(rest.is_empty());
        let Frame::Avl(packet) = Frame::from(decoded) else {
            panic!("expected AVL frame")
        };
        prop_assert_eq!(packet.codec(), AvlCodec::Codec8);
        prop_assert_eq!(packet.records().len(), recipes.len());
        for (record, recipe) in packet.records().iter().zip(&recipes) {
            assert_record_matches(record, recipe, AvlCodec::Codec8);
        }
    }

    #[test]
    fn codec8_extended_frame_round_trips((bytes, recipes) in avl_frame(AvlCodec::Codec8Extended)) {
        let mut rest = &bytes[..];
        let decoded = take_frame(&mut rest).expect("frame built by the strategy must be valid");
        prop_assert!(rest.is_empty());
        let Frame::Avl(packet) = Frame::from(decoded) else {
            panic!("expected AVL frame")
        };
        prop_assert_eq!(packet.codec(), AvlCodec::Codec8Extended);
        prop_assert_eq!(packet.records().len(), recipes.len());
        for (record, recipe) in packet.records().iter().zip(&recipes) {
            assert_record_matches(record, recipe, AvlCodec::Codec8Extended);
        }
    }

    #[test]
    fn codec16_frame_round_trips((bytes, recipes) in avl_frame(AvlCodec::Codec16)) {
        let mut rest = &bytes[..];
        let decoded = take_frame(&mut rest).expect("frame built by the strategy must be valid");
        prop_assert!(rest.is_empty());
        let Frame::Avl(packet) = Frame::from(decoded) else {
            panic!("expected AVL frame")
        };
        prop_assert_eq!(packet.codec(), AvlCodec::Codec16);
        prop_assert_eq!(packet.records().len(), recipes.len());
        for (record, recipe) in packet.records().iter().zip(&recipes) {
            assert_record_matches(record, recipe, AvlCodec::Codec16);
        }
    }

    #[test]
    fn codec12_frame_round_trips((bytes, expected_messages) in codec12_frame()) {
        let mut rest = &bytes[..];
        let decoded = take_frame(&mut rest).expect("frame built by the strategy must be valid");
        prop_assert!(rest.is_empty());
        let Frame::Gprs(packet) = Frame::from(decoded) else {
            panic!("expected Codec 12 frame")
        };
        let payloads: Vec<&[u8]> = packet.messages().iter().map(|message| message.payload()).collect();
        let expected: Vec<&[u8]> = expected_messages.iter().map(Vec::as_slice).collect();
        prop_assert_eq!(payloads, expected);
    }

    // The following four properties make no assertion on the outcome:
    // arbitrary single-byte corruption at a random offset has no single
    // expected result. The frame may still decode, or fail with any error.
    // They check that decoding never panics and that the cursor contract
    // holds: untouched unless the frame was delimited.

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

    #[test]
    fn codec8_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in avl_frame_with_corruption(AvlCodec::Codec8)
    ) {
        check_corrupted(bytes, index, replacement)?;
    }

    #[test]
    fn codec8_extended_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in avl_frame_with_corruption(AvlCodec::Codec8Extended)
    ) {
        check_corrupted(bytes, index, replacement)?;
    }

    #[test]
    fn codec16_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in avl_frame_with_corruption(AvlCodec::Codec16)
    ) {
        check_corrupted(bytes, index, replacement)?;
    }

    #[test]
    fn codec12_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in codec12_frame_with_corruption()
    ) {
        check_corrupted(bytes, index, replacement)?;
    }
}

fn check_corrupted(mut bytes: Vec<u8>, index: usize, replacement: u8) -> Result<(), TestCaseError> {
    bytes[index] = replacement;
    let mut rest = &bytes[..];
    match take_frame(&mut rest) {
        Ok(_) | Err(DecodeFrameError::InvalidFrame { .. }) => {
            // Delimited: the cursor is past the frame, as long as the length
            // field wasn't corrupted.
            if !(4..8).contains(&index) {
                prop_assert!(rest.is_empty());
            }
        }
        Err(DecodeFrameError::Incomplete { .. } | DecodeFrameError::InvalidHeader(_)) => {
            prop_assert_eq!(rest.len(), bytes.len());
        }
    }
    Ok(())
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

/// Encodes `recipes` with the library encoder, reading each field as the
/// strategy's own encoder writes it for `codec`.
fn encode_with_library(codec: AvlCodec, recipes: &[AvlRecordRecipe]) -> Vec<u8> {
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
    encode_avl_frame(codec, &records).expect("strategy records fit their codec")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    // The strategy's encoder is written independently from the library's,
    // from the wiki layouts; both must produce the same bytes.

    #[test]
    fn codec8_library_encoder_matches_the_reference((bytes, recipes) in avl_frame(AvlCodec::Codec8)) {
        prop_assert_eq!(encode_with_library(AvlCodec::Codec8, &recipes), bytes);
    }

    #[test]
    fn codec8_extended_library_encoder_matches_the_reference(
        (bytes, recipes) in avl_frame(AvlCodec::Codec8Extended)
    ) {
        prop_assert_eq!(encode_with_library(AvlCodec::Codec8Extended, &recipes), bytes);
    }

    #[test]
    fn codec16_library_encoder_matches_the_reference((bytes, recipes) in avl_frame(AvlCodec::Codec16)) {
        prop_assert_eq!(encode_with_library(AvlCodec::Codec16, &recipes), bytes);
    }
}
