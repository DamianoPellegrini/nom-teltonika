mod common;

use common::strategies::{
    AvlRecordRecipe, avl_frame, avl_frame_with_corruption, codec12_frame,
    codec12_frame_with_corruption,
};
use nom_teltonika::{
    decoder::decode_tcp_frame,
    protocol::{AvlCodec, AvlRecord, Frame, GenerationType, IoId, IoValue, Priority},
};
use proptest::prelude::*;

/// Asserts `record` holds exactly what `recipe` specified, accounting for the
/// per-codec wire truncations `encode_record` applies (1-byte event id and IO
/// ids for Codec8; no generation type outside Codec16; no extended-bytes IO
/// group outside Codec8 Extended).
fn assert_record_matches(record: &AvlRecord, recipe: &AvlRecordRecipe, codec: AvlCodec) {
    assert_eq!(record.timestamp.unix_millis(), recipe.timestamp);

    let expected_priority = match recipe.priority {
        0 => Priority::Low,
        1 => Priority::High,
        2 => Priority::Panic,
        other => panic!("strategy generated invalid priority {other}"),
    };
    assert_eq!(record.priority, expected_priority);

    assert_eq!(record.gps.longitude_raw, recipe.longitude);
    assert_eq!(record.gps.latitude_raw, recipe.latitude);
    assert_eq!(record.gps.altitude_meters, recipe.altitude);
    assert_eq!(record.gps.angle_degrees, recipe.angle);
    assert_eq!(record.gps.satellites, recipe.satellites);
    assert_eq!(record.gps.speed_kph, recipe.speed);

    let expected_event_id = if codec == AvlCodec::Codec8 {
        u16::from(recipe.event_id as u8)
    } else {
        recipe.event_id
    };
    let expected_event = (expected_event_id != 0).then(|| IoId::new(expected_event_id));
    assert_eq!(record.event_io_id, expected_event);

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
        assert_eq!(record.generation_type, Some(expected_generation));
    } else {
        assert_eq!(record.generation_type, None);
    }

    let id_of = |id: u16| -> IoId {
        if codec == AvlCodec::Codec8 {
            IoId::new(u16::from(id as u8))
        } else {
            IoId::new(id)
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
            expected.push((IoId::new(*id), IoValue::Bytes(value.clone())));
        }
    }

    let actual: Vec<(IoId, IoValue)> = record
        .io_elements
        .iter()
        .map(|element| (element.id, element.value.clone()))
        .collect();
    assert_eq!(actual, expected);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn codec8_frame_round_trips((bytes, recipes) in avl_frame(AvlCodec::Codec8)) {
        let decoded = decode_tcp_frame(&bytes).expect("frame built by the strategy must be valid");
        prop_assert_eq!(decoded.consumed, bytes.len());
        let Frame::Avl(packet) = decoded.value else {
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
        let decoded = decode_tcp_frame(&bytes).expect("frame built by the strategy must be valid");
        prop_assert_eq!(decoded.consumed, bytes.len());
        let Frame::Avl(packet) = decoded.value else {
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
        let decoded = decode_tcp_frame(&bytes).expect("frame built by the strategy must be valid");
        prop_assert_eq!(decoded.consumed, bytes.len());
        let Frame::Avl(packet) = decoded.value else {
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
        let decoded = decode_tcp_frame(&bytes).expect("frame built by the strategy must be valid");
        prop_assert_eq!(decoded.consumed, bytes.len());
        let Frame::Codec12(packet) = decoded.value else {
            panic!("expected Codec 12 frame")
        };
        prop_assert_eq!(packet.message().payloads().len(), expected_messages);
    }

    // The following four properties intentionally make no assertion beyond
    // "does not panic": arbitrary single-byte corruption at a random offset
    // has no single expected outcome — the frame may still happen to decode,
    // or fail with any DecodeError variant, depending on which byte was hit.
    // proptest already fails the case if decode_tcp_frame panics, which is
    // the entire property.

    #[test]
    fn codec8_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in avl_frame_with_corruption(AvlCodec::Codec8)
    ) {
        let mut corrupted = bytes;
        corrupted[index] = replacement;
        let _ = decode_tcp_frame(&corrupted);
    }

    #[test]
    fn codec8_extended_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in avl_frame_with_corruption(AvlCodec::Codec8Extended)
    ) {
        let mut corrupted = bytes;
        corrupted[index] = replacement;
        let _ = decode_tcp_frame(&corrupted);
    }

    #[test]
    fn codec16_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in avl_frame_with_corruption(AvlCodec::Codec16)
    ) {
        let mut corrupted = bytes;
        corrupted[index] = replacement;
        let _ = decode_tcp_frame(&corrupted);
    }

    #[test]
    fn codec12_frame_survives_single_byte_corruption(
        (bytes, index, replacement) in codec12_frame_with_corruption()
    ) {
        let mut corrupted = bytes;
        corrupted[index] = replacement;
        let _ = decode_tcp_frame(&corrupted);
    }
}
