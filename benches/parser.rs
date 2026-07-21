use std::{hint::black_box, io::Cursor};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nom_teltonika::{
    Limits, StreamConfig, TeltonikaStream, encode_codec12_command, parse_tcp_frame,
};

const CODEC8: &str = "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF";

fn parser_benchmarks(criterion: &mut Criterion) {
    let frame = hex::decode(CODEC8).unwrap();
    let mut group = criterion.benchmark_group("tcp_codec8");
    group.throughput(Throughput::Bytes(frame.len() as u64));
    group.bench_function("owned_one_pass", |bench| {
        bench.iter(|| parse_tcp_frame(black_box(&frame)).unwrap())
    });
    group.finish();

    let large_frame = encode_codec12_command(&vec![0x55; 48 * 1024]);
    let mut stream_group = criterion.benchmark_group("stream_codec12_48k");
    stream_group.throughput(Throughput::Bytes(large_frame.len() as u64));
    for chunk_size in [2 * 1024, 4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024] {
        stream_group.bench_with_input(
            BenchmarkId::new("stream", chunk_size),
            &chunk_size,
            |bench, chunk_size| {
                bench.iter(|| {
                    let config = StreamConfig::new(*chunk_size, Limits::default()).unwrap();
                    let mut stream =
                        TeltonikaStream::with_config(Cursor::new(large_frame.clone()), config)
                            .unwrap();
                    black_box(stream.read_frame().unwrap())
                });
            },
        );
    }
    stream_group.finish();
}

criterion_group!(benches, parser_benchmarks);
criterion_main!(benches);
