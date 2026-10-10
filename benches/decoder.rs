//! Decoding and stream benchmarks on inputs built by the library's encoders.
//!
//! Inputs cover each AVL codec at one record, ten records, and the most
//! records that fit in a frame, plus Codec 12 frames read through
//! the stream at several read sizes, and bursts of full Codec 16 frames
//! that make the stream's buffer grow.
//!
//! The `bulk_*` groups run on 64 MiB of mixed traffic: every codec, both
//! record shapes, and every record count, with values that change from one
//! record to the next. Such an input doesn't fit in any cache, so these
//! groups measure what a server sustains, where the others measure one
//! frame that stays in the first-level cache.

use std::{
    hint::black_box,
    io::{self, Cursor, Read},
    sync::LazyLock,
};

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use nom_teltonika::{
    decoder::{take_datagram, take_frame},
    encoder::{
        AvlRecordFields, DatagramHeaderFields, EncodeAvlError, encode_avl_datagram,
        encode_avl_frame, encode_avl_frame_into, encode_gprs_frame,
    },
    protocol::{
        AvlCodec, AvlTimestamp, FrameView, GenerationType, GprsMessageType, GpsElement, ImeiView,
        IoId, Priority,
    },
    tcp::{ReadFrameError, TeltonikaTcpStream},
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
                        let FrameView::Avl(packet) = frame else {
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
            bench.iter(|| encode_avl_frame_into(codec, black_box(&records), &mut out).unwrap())
        });
    }
    group.finish();
}

/// Bytes of traffic in each bulk input.
const BULK_LEN: usize = 64 * 1024 * 1024;

/// Most records in a bulk packet, when that many fit.
const BULK_MAX_RECORDS: usize = 32;

const CODECS: [AvlCodec; 3] = [
    AvlCodec::Codec8,
    AvlCodec::Codec8Extended,
    AvlCodec::Codec16,
];

// The IO elements an FMB003 sends in every record, by width: 6, 11, 3, and
// 2, plus the 17-byte VIN an FM3001 adds in Codec 8 Extended. IDs are from
// "FMB Teltonika Data Sending Parameters ID"; the values are arbitrary.
static FULL_IO_U8: LazyLock<[(IoId, u8); 6]> = LazyLock::new(|| {
    [
        (239.into(), 1),
        (240.into(), 1),
        (80.into(), 1),
        (21.into(), 4),
        (200.into(), 0),
        (69.into(), 1),
    ]
});
static FULL_IO_U16: LazyLock<[(IoId, u16); 11]> = LazyLock::new(|| {
    [
        (181.into(), 12),
        (182.into(), 8),
        (66.into(), 13_800),
        (24.into(), 42),
        (205.into(), 51_234),
        (206.into(), 3_210),
        (67.into(), 4_050),
        (68.into(), 0),
        (17.into(), 65_500),
        (18.into(), 30),
        (19.into(), 1_010),
    ]
});
static FULL_IO_U32: LazyLock<[(IoId, u32); 3]> = LazyLock::new(|| {
    [
        (241.into(), 22_201),
        (199.into(), 1_500),
        (16.into(), 123_456),
    ]
});
static FULL_IO_U64: LazyLock<[(IoId, u64); 2]> = LazyLock::new(|| {
    [
        (11.into(), 0x0000_0014_f0e5_3d21),
        (14.into(), 0x0000_0002_1d7a_0c4b),
    ]
});
static FULL_IO_BYTES: LazyLock<[(IoId, &[u8]); 1]> =
    LazyLock::new(|| [(256.into(), b"WVWZZZ1JZXW000001")]);

/// A xorshift64 generator, so that the bulk inputs are the same on every
/// run and machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Returns a value in `0..bound`.
    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// Returns one record for `codec` with a position, a time, and a priority
/// from `rng`: the five IO elements of [`records`], or the 22 of an FMB003
/// when `full`.
fn bulk_record(rng: &mut Rng, codec: AvlCodec, full: bool) -> AvlRecordFields<'static> {
    let gps = GpsElement {
        longitude_raw: (rng.below(3_600_000_000) as i64 - 1_800_000_000) as i32,
        latitude_raw: rng.below(1_800_000_000) as i32 - 900_000_000,
        altitude_meters: rng.below(3_000) as u16,
        angle_degrees: rng.below(360) as u16,
        satellites: rng.below(20) as u8,
        speed_kph: rng.below(180) as u16,
    };
    let millis = 1_700_000_000_000 + rng.below(1 << 36) as u64;
    let priority = match rng.below(16) {
        0 => Priority::High,
        1 => Priority::Panic,
        _ => Priority::Low,
    };
    let mut record = AvlRecordFields::new(AvlTimestamp::from(millis), priority, gps);
    record = if full {
        record
            .with_io_u8(&*FULL_IO_U8)
            .with_io_u16(&*FULL_IO_U16)
            .with_io_u32(&*FULL_IO_U32)
            .with_io_u64(&*FULL_IO_U64)
    } else {
        record
            .with_io_u8(&*IO_U8)
            .with_io_u16(&*IO_U16)
            .with_io_u32(&*IO_U32)
            .with_io_u64(&*IO_U64)
    };
    if rng.below(8) == 0 {
        record = record.with_event_io_id(239.into());
    }
    match codec {
        AvlCodec::Codec8Extended if full => record.with_io_bytes(&*FULL_IO_BYTES),
        AvlCodec::Codec8Extended => record.with_io_bytes(&*IO_BYTES),
        AvlCodec::Codec16 => record.with_generation_type(GenerationType::Periodical),
        _ => record,
    }
}

/// Returns the records of one bulk packet: a codec, a shape, and a count
/// from `rng`, up to [`BULK_MAX_RECORDS`] records or as many as fit in a
/// frame of the codec.
fn bulk_packet(rng: &mut Rng) -> (AvlCodec, Vec<AvlRecordFields<'static>>) {
    let codec = CODECS[rng.below(CODECS.len())];
    let full = rng.below(2) == 0;
    let mut records: Vec<_> = (0..1 + rng.below(BULK_MAX_RECORDS))
        .map(|_| bulk_record(rng, codec, full))
        .collect();
    while let Err(EncodeAvlError::TooLong { .. }) = encode_avl_frame_into(codec, &records, &mut [])
    {
        records.pop();
    }
    (codec, records)
}

/// Returns [`BULK_LEN`] bytes of frames back to back, and their number: AVL
/// packets from [`bulk_packet`], and a Codec 12 response in every 64 frames.
fn bulk_frames() -> (Vec<u8>, usize) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let response = encode_gprs_frame(
        GprsMessageType::Response,
        &["RTC:2023/11/14 22:13 Init:2023/11/14 5:22 UpTime:60663s PWR:SoftReset RST:0 GPS:3 SAT:9 TTFF:21 TTLF:0 NOGPS: 0:0 SR:1234 FG:0 FL:0 SMS:0 REC:0 MD:1 DB:0"],
    )
    .unwrap();
    let mut out = Vec::with_capacity(BULK_LEN + MAX_BULK_UNIT_LEN);
    let mut count = 0;
    while out.len() < BULK_LEN {
        if count % 64 == 63 {
            out.extend_from_slice(&response);
        } else {
            let (codec, records) = bulk_packet(&mut rng);
            out.extend_from_slice(&encode_avl_frame(codec, &records).unwrap());
        }
        count += 1;
    }
    (out, count)
}

/// Upper bound of a bulk frame or datagram: 32 Codec 16 records of 22 IO
/// elements take about 4.3 kB.
const MAX_BULK_UNIT_LEN: usize = 8 * 1024;

/// Returns [`BULK_LEN`] bytes of datagrams back to back, and their number.
/// Each one starts with the length of what follows, which delimits it.
fn bulk_datagrams() -> (Vec<u8>, usize) {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let imei = ImeiView::try_from("352093086403655").unwrap();
    let mut out = Vec::with_capacity(BULK_LEN + MAX_BULK_UNIT_LEN);
    let mut count = 0;
    while out.len() < BULK_LEN {
        let (codec, records) = bulk_packet(&mut rng);
        let header = DatagramHeaderFields {
            packet_id: count as u16,
            avl_packet_id: count as u8,
            imei,
        };
        out.extend_from_slice(&encode_avl_datagram(header, codec, &records).unwrap());
        count += 1;
    }
    (out, count)
}

/// A transport that hands over at most one TCP segment per read: 1460 bytes,
/// the payload of a segment on Ethernet.
struct Segments<'a>(&'a [u8]);

impl Read for Segments<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = self.0.len().min(out.len()).min(1460);
        let (segment, rest) = self.0.split_at(len);
        out[..len].copy_from_slice(segment);
        self.0 = rest;
        Ok(len)
    }
}

/// Reads frames from `stream` until it closes, and returns their number.
fn read_to_end<R: Read>(mut stream: TeltonikaTcpStream<R>) -> usize {
    let mut count = 0;
    loop {
        match stream.read_frame() {
            Ok(frame) => {
                black_box(frame.codec());
                count += 1;
            }
            Err(ReadFrameError::Closed) => return count,
            Err(error) => panic!("{error}"),
        }
    }
}

fn bulk(criterion: &mut Criterion) {
    let (frames, frame_count) = bulk_frames();
    let mut group = criterion.benchmark_group("bulk_tcp");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(frames.len() as u64));
    group.bench_function("validate", |bench| {
        bench.iter(|| {
            let mut input = black_box(&frames[..]);
            let mut count = 0;
            while !input.is_empty() {
                black_box(take_frame(&mut input).unwrap());
                count += 1;
            }
            assert_eq!(count, frame_count);
        })
    });
    group.bench_function("iterate", |bench| {
        bench.iter(|| {
            let mut input = black_box(&frames[..]);
            let mut elements = 0;
            while !input.is_empty() {
                if let FrameView::Avl(packet) = take_frame(&mut input).unwrap() {
                    elements += packet
                        .records()
                        .map(|record| record.io_elements().count())
                        .sum::<usize>();
                }
            }
            elements
        })
    });
    group.bench_function("evaluate", |bench| {
        bench.iter(|| {
            let mut input = black_box(&frames[..]);
            while !input.is_empty() {
                black_box(take_frame(&mut input).unwrap().evaluate());
            }
        })
    });
    for capacity in [1280, 64 * 1024] {
        group.bench_function(BenchmarkId::new("stream", capacity), |bench| {
            bench.iter(|| {
                let stream = TeltonikaTcpStream::with_capacity(capacity, Cursor::new(&frames[..]));
                assert_eq!(read_to_end(stream), frame_count);
            })
        });
        group.bench_function(BenchmarkId::new("stream_segments", capacity), |bench| {
            bench.iter(|| {
                let stream = TeltonikaTcpStream::with_capacity(capacity, Segments(&frames));
                assert_eq!(read_to_end(stream), frame_count);
            })
        });
    }
    group.finish();

    let (datagrams, datagram_count) = bulk_datagrams();
    let mut group = criterion.benchmark_group("bulk_udp");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(datagrams.len() as u64));
    group.bench_function("validate", |bench| {
        bench.iter(|| {
            let mut input = black_box(&datagrams[..]);
            let mut count = 0;
            while let Some((length, _)) = input.split_first_chunk() {
                let (mut datagram, rest) =
                    input.split_at(2 + usize::from(u16::from_be_bytes(*length)));
                black_box(take_datagram(&mut datagram).unwrap());
                input = rest;
                count += 1;
            }
            assert_eq!(count, datagram_count);
        })
    });
    group.finish();

    // Encoding has no input to read, so its bulk is the output: the frames
    // of the same packets as `bulk_tcp`, written one after the other.
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let packets: Vec<_> = (0..4096).map(|_| bulk_packet(&mut rng)).collect();
    let mut out = vec![0; MAX_BULK_UNIT_LEN];
    let pass: usize = packets
        .iter()
        .map(|(codec, records)| encode_avl_frame_into(*codec, records, &mut out).unwrap())
        .sum();
    let passes = BULK_LEN.div_ceil(pass);
    let mut group = criterion.benchmark_group("bulk_encode");
    group.sample_size(10);
    group.throughput(Throughput::Bytes((pass * passes) as u64));
    group.bench_function("avl_frames", |bench| {
        bench.iter(|| {
            for _ in 0..passes {
                for (codec, records) in black_box(&packets) {
                    black_box(encode_avl_frame_into(*codec, records, &mut out).unwrap());
                }
            }
        })
    });
    group.finish();
}

criterion_group!(benches, avl_decoding, stream_reading, avl_encoding, bulk);
criterion_main!(benches);
