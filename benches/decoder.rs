//! Decoding and stream benchmarks on inputs built by the library's encoders.
//!
//! Inputs cover each AVL codec at one record, ten records, and the most
//! records that fit in a frame, plus Codec 12 frames read through
//! the stream at several read sizes, and bursts of full Codec 16 frames
//! that make the stream's buffer grow.

use std::{hint::black_box, io::Cursor, sync::LazyLock};

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use nom_teltonika::{
    decoder::{take_datagram, take_frame},
    encoder::{
        AvlRecordFields, DatagramHeaderFields, EncodeAvlError, encode_avl_datagram,
        encode_avl_frame, encode_gprs_frame,
    },
    protocol::{
        AvlCodec, AvlTimestamp, GenerationType, GprsMessageType, GpsElement, ImeiView, IoId,
        Priority,
    },
    tcp::TeltonikaTcpStream,
};

const GPS: GpsElement = GpsElement {
    longitude_raw: 252_800_000,
    latitude_raw: 546_900_000,
    altitude_meters: 110,
    angle_degrees: 90,
    satellites: 9,
    speed_kph: 42,
};

// FMB IO IDs: ignition, movement, external voltage, odometer, iButton, and a
// variable-length beacon element for Codec 8 Extended.
static IO_U8: LazyLock<[(IoId, u8); 2]> = LazyLock::new(|| [(239.into(), 1), (240.into(), 1)]);
static IO_U16: LazyLock<[(IoId, u16); 1]> = LazyLock::new(|| [(66.into(), 13_800)]);
static IO_U32: LazyLock<[(IoId, u32); 1]> = LazyLock::new(|| [(16.into(), 123_456)]);
static IO_U64: LazyLock<[(IoId, u64); 1]> = LazyLock::new(|| [(78.into(), 0x0102_0304_0506_0708)]);
static IO_BYTES: LazyLock<[(IoId, &[u8]); 1]> = LazyLock::new(|| [(385.into(), &[0xab; 12])]);

/// Returns `count` typical records for `codec`: five fixed-width IO
/// elements, plus a 12-byte one in Codec 8 Extended.
fn records(codec: AvlCodec, count: usize) -> Vec<AvlRecordFields<'static>> {
    (0..count)
        .map(|index| {
            let millis = 1_700_000_000_000 + 1_000 * index as u64;
            let mut record = AvlRecordFields::new(AvlTimestamp::from(millis), Priority::Low, GPS)
                .with_io_u8(&*IO_U8)
                .with_io_u16(&*IO_U16)
                .with_io_u32(&*IO_U32)
                .with_io_u64(&*IO_U64);
            match codec {
                AvlCodec::Codec8Extended => record = record.with_io_bytes(&*IO_BYTES),
                AvlCodec::Codec16 => {
                    record = record.with_generation_type(GenerationType::Periodical);
                }
                _ => {}
            }
            record
        })
        .collect()
}

/// Returns the frame with the most typical records that fit, and its count.
fn fullest_frame(codec: AvlCodec) -> (Vec<u8>, usize) {
    (1..=255)
        .map_while(
            |count| match encode_avl_frame(codec, &records(codec, count)) {
                Ok(frame) => Some((frame, count)),
                Err(EncodeAvlError::TooLong { .. }) => None,
                Err(error) => panic!("{error}"),
            },
        )
        .last()
        .expect("one record fits")
}

fn avl_decoding(criterion: &mut Criterion) {
    for (codec, name) in [
        (AvlCodec::Codec8, "codec8"),
        (AvlCodec::Codec8Extended, "codec8e"),
        (AvlCodec::Codec16, "codec16"),
    ] {
        let mut group = criterion.benchmark_group(format!("tcp_{name}"));
        let full = fullest_frame(codec);
        let one = (encode_avl_frame(codec, &records(codec, 1)).unwrap(), 1);
        let ten = (encode_avl_frame(codec, &records(codec, 10)).unwrap(), 10);
        for (frame, count) in [one, ten, full] {
            group.throughput(Throughput::Bytes(frame.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("validate", count),
                &frame,
                |bench, frame| bench.iter(|| take_frame(&mut black_box(&frame[..])).unwrap()),
            );
            group.bench_with_input(
                BenchmarkId::new("iterate", count),
                &frame,
                |bench, frame| {
                    bench.iter(|| {
                        let frame = take_frame(&mut black_box(&frame[..])).unwrap();
                        let nom_teltonika::protocol::FrameView::Avl(packet) = frame else {
                            unreachable!("an AVL frame")
                        };
                        packet
                            .records()
                            .map(|record| record.io_elements().count())
                            .sum::<usize>()
                    })
                },
            );
            group.bench_with_input(
                BenchmarkId::new("evaluate", count),
                &frame,
                |bench, frame| {
                    bench.iter(|| take_frame(&mut black_box(&frame[..])).unwrap().evaluate())
                },
            );
        }
        group.finish();
    }

    let header = DatagramHeaderFields {
        packet_id: 0xcafe,
        avl_packet_id: 5,
        imei: ImeiView::try_from("352093086403655").unwrap(),
    };
    let datagram =
        encode_avl_datagram(header, AvlCodec::Codec8, &records(AvlCodec::Codec8, 10)).unwrap();
    let mut group = criterion.benchmark_group("udp_codec8");
    group.throughput(Throughput::Bytes(datagram.len() as u64));
    group.bench_function("validate/10", |bench| {
        bench.iter(|| take_datagram(&mut black_box(&datagram[..])).unwrap())
    });
    group.finish();
}

fn stream_reading(criterion: &mut Criterion) {
    // Ten full Codec 8 Extended frames back to back, as a busy device sends.
    let (frame, _) = fullest_frame(AvlCodec::Codec8Extended);
    let frames = frame.repeat(10);
    let mut group = criterion.benchmark_group("stream_codec8e_10_frames");
    group.throughput(Throughput::Bytes(frames.len() as u64));
    for capacity in [1280, 4 * 1024, 16 * 1024] {
        bench_capacity(&mut group, capacity, &frames, 10);
    }
    group.finish();

    let large_frame =
        encode_gprs_frame(GprsMessageType::Response, &[vec![0x55; 32 * 1024]]).unwrap();
    let mut group = criterion.benchmark_group("stream_codec12_32k");
    group.throughput(Throughput::Bytes(large_frame.len() as u64));
    // 1280 and 8 KiB grow once for the frame; 40 KiB holds it from the start.
    for capacity in [1280, 8 * 1024, 40 * 1024] {
        bench_capacity(&mut group, capacity, &large_frame, 1);
    }
    group.finish();

    // What growing costs per frame, by burst length: one frame, a short
    // burst, and a long one, all of full Codec 16 frames (255 records,
    // about 14.8 KB). From 1280 bytes the buffer grows once, to 16 KiB, on
    // the first frame; from 16 KiB it never grows, so the difference
    // between the two is the growth alone. The throughput is in frames.
    let frame = encode_avl_frame(AvlCodec::Codec16, &records(AvlCodec::Codec16, 255)).unwrap();
    let mut group = criterion.benchmark_group("stream_codec16_burst");
    for burst in [1, 3, 100] {
        let input = frame.repeat(burst);
        group.throughput(Throughput::Elements(burst as u64));
        for (name, capacity) in [("grown_from_1280", 1280), ("held_by_16384", 16 * 1024)] {
            group.bench_with_input(BenchmarkId::new(name, burst), &input, |bench, input| {
                bench.iter(|| {
                    let mut stream =
                        TeltonikaTcpStream::with_capacity(capacity, Cursor::new(input));
                    for _ in 0..burst {
                        black_box(stream.read_frame().unwrap().codec());
                    }
                });
            });
        }
    }
    group.finish();
}

/// Reads `count` frames from `input` through a stream of `capacity` bytes.
fn bench_capacity(
    group: &mut BenchmarkGroup<'_, WallTime>,
    capacity: usize,
    input: &[u8],
    count: usize,
) {
    group.bench_with_input(
        BenchmarkId::new("capacity", capacity),
        input,
        |bench, input| {
            bench.iter(|| {
                let mut stream = TeltonikaTcpStream::with_capacity(capacity, Cursor::new(input));
                for _ in 0..count {
                    black_box(stream.read_frame().unwrap().codec());
                }
            });
        },
    );
}

fn avl_encoding(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("encode_avl");
    for (codec, name) in [
        (AvlCodec::Codec8, "codec8"),
        (AvlCodec::Codec8Extended, "codec8e"),
        (AvlCodec::Codec16, "codec16"),
    ] {
        let records = records(codec, 10);
        let mut out = [0; 1280];
        group.bench_function(format!("{name}/10"), |bench| {
            bench.iter(|| {
                nom_teltonika::encoder::encode_avl_frame_into(codec, black_box(&records), &mut out)
                    .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, avl_decoding, stream_reading, avl_encoding);
criterion_main!(benches);
