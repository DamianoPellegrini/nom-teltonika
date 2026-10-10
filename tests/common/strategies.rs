#![allow(dead_code)]

use nom_teltonika::{
    encoder::encode_gprs_frame,
    protocol::{AvlCodec, GprsMessageType},
};
use proptest::prelude::*;
use proptest::{collection, sample};

use super::tcp_frame_from_data;

/// Random-but-consistent field values for one AVL record, before encoding.
#[derive(Debug, Clone)]
pub struct AvlRecordRecipe {
    pub timestamp: u64,
    pub priority: u8,
    pub longitude: i32,
    pub latitude: i32,
    pub altitude: u16,
    pub angle: u16,
    pub satellites: u8,
    pub speed: u16,
    pub event_id: u16,
    pub generation_type: u8,
    pub io_u8: Vec<(u16, u8)>,
    pub io_u16: Vec<(u16, u16)>,
    pub io_u32: Vec<(u16, u32)>,
    pub io_u64: Vec<(u16, u64)>,
    pub io_bytes: Vec<(u16, Vec<u8>)>,
}

prop_compose! {
    fn avl_record_recipe()(
        timestamp in any::<u64>(),
        priority in sample::select(vec![0u8, 1, 2]),
        longitude in any::<i32>(),
        latitude in any::<i32>(),
        altitude in any::<u16>(),
        angle in any::<u16>(),
        satellites in any::<u8>(),
        speed in any::<u16>(),
        event_id in any::<u16>(),
        generation_type in sample::select(vec![0u8, 1, 2, 3, 4, 5, 6, 7]),
        io_u8 in collection::vec((any::<u16>(), any::<u8>()), 0..=3),
        io_u16 in collection::vec((any::<u16>(), any::<u16>()), 0..=3),
        io_u32 in collection::vec((any::<u16>(), any::<u32>()), 0..=3),
        io_u64 in collection::vec((any::<u16>(), any::<u64>()), 0..=3),
        io_bytes in collection::vec(
            (any::<u16>(), collection::vec(any::<u8>(), 0..=6)),
            0..=3,
        ),
    ) -> AvlRecordRecipe {
        AvlRecordRecipe {
            timestamp,
            priority,
            longitude,
            latitude,
            altitude,
            angle,
            satellites,
            speed,
            event_id,
            generation_type,
            io_u8,
            io_u16,
            io_u32,
            io_u64,
            io_bytes,
        }
    }
}

fn push_count(out: &mut Vec<u8>, codec: AvlCodec, count: u16) {
    if codec == AvlCodec::Codec8Extended {
        out.extend_from_slice(&count.to_be_bytes());
    } else {
        out.push(count as u8);
    }
}

fn push_id(out: &mut Vec<u8>, codec: AvlCodec, id: u16) {
    if codec == AvlCodec::Codec8 {
        out.push(id as u8);
    } else {
        out.extend_from_slice(&id.to_be_bytes());
    }
}

/// Encodes one record with the given codec's field widths.
fn encode_record(codec: AvlCodec, recipe: &AvlRecordRecipe) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&recipe.timestamp.to_be_bytes());
    out.push(recipe.priority);
    out.extend_from_slice(&recipe.longitude.to_be_bytes());
    out.extend_from_slice(&recipe.latitude.to_be_bytes());
    out.extend_from_slice(&recipe.altitude.to_be_bytes());
    out.extend_from_slice(&recipe.angle.to_be_bytes());
    out.push(recipe.satellites);
    out.extend_from_slice(&recipe.speed.to_be_bytes());

    if codec == AvlCodec::Codec8 {
        out.push(recipe.event_id as u8);
    } else {
        out.extend_from_slice(&recipe.event_id.to_be_bytes());
    }

    if codec == AvlCodec::Codec16 {
        out.push(recipe.generation_type);
    }

    // "N = N1 + N2 + N4 + N8" (https://wiki.teltonika-gps.com/view/Codec,
    // "Codec 8 Extended > IO Element", accessed 2026-09-24), plus NX in
    // Codec 8 Extended, as devices send it.
    let mut total =
        recipe.io_u8.len() + recipe.io_u16.len() + recipe.io_u32.len() + recipe.io_u64.len();
    if codec == AvlCodec::Codec8Extended {
        total += recipe.io_bytes.len();
    }
    let total = total as u16;
    push_count(&mut out, codec, total);

    push_count(&mut out, codec, recipe.io_u8.len() as u16);
    for (id, value) in &recipe.io_u8 {
        push_id(&mut out, codec, *id);
        out.push(*value);
    }
    push_count(&mut out, codec, recipe.io_u16.len() as u16);
    for (id, value) in &recipe.io_u16 {
        push_id(&mut out, codec, *id);
        out.extend_from_slice(&value.to_be_bytes());
    }
    push_count(&mut out, codec, recipe.io_u32.len() as u16);
    for (id, value) in &recipe.io_u32 {
        push_id(&mut out, codec, *id);
        out.extend_from_slice(&value.to_be_bytes());
    }
    push_count(&mut out, codec, recipe.io_u64.len() as u16);
    for (id, value) in &recipe.io_u64 {
        push_id(&mut out, codec, *id);
        out.extend_from_slice(&value.to_be_bytes());
    }

    if codec == AvlCodec::Codec8Extended {
        push_count(&mut out, codec, recipe.io_bytes.len() as u16);
        for (id, value) in &recipe.io_bytes {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
    }

    out
}

/// Assembles a complete, CRC-correct TCP frame from already-generated records.
pub fn build_avl_frame(codec: AvlCodec, records: &[AvlRecordRecipe]) -> Vec<u8> {
    let mut data = vec![u8::from(codec), records.len() as u8];
    for record in records {
        data.extend_from_slice(&encode_record(codec, record));
    }
    data.push(records.len() as u8);
    tcp_frame_from_data(&data)
}

/// A structurally valid AVL frame for `codec`, alongside the record recipes it encodes.
pub fn avl_frame(codec: AvlCodec) -> impl Strategy<Value = (Vec<u8>, Vec<AvlRecordRecipe>)> {
    collection::vec(avl_record_recipe(), 1..=3)
        .prop_map(move |records| (build_avl_frame(codec, &records), records))
}

/// A valid AVL frame for `codec` plus a random byte offset and replacement byte.
pub fn avl_frame_with_corruption(codec: AvlCodec) -> impl Strategy<Value = (Vec<u8>, usize, u8)> {
    avl_frame(codec).prop_flat_map(|(bytes, _records)| {
        let len = bytes.len();
        (Just(bytes), 0..len, any::<u8>())
    })
}

/// A structurally valid Codec 12 command frame, alongside the commands it encodes.
pub fn codec12_frame() -> impl Strategy<Value = (Vec<u8>, Vec<Vec<u8>>)> {
    collection::vec(collection::vec(any::<u8>(), 0..=16), 1..=4).prop_map(|commands| {
        let refs: Vec<&[u8]> = commands.iter().map(Vec::as_slice).collect();
        let bytes = encode_gprs_frame(GprsMessageType::Command, &refs)
            .expect("1..=4 small commands always encode");
        (bytes, commands)
    })
}

/// A valid Codec 12 frame plus a random byte offset and replacement byte.
pub fn codec12_frame_with_corruption() -> impl Strategy<Value = (Vec<u8>, usize, u8)> {
    codec12_frame().prop_flat_map(|(bytes, _commands)| {
        let len = bytes.len();
        (Just(bytes), 0..len, any::<u8>())
    })
}
