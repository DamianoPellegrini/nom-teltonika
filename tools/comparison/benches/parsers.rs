//! Every parser of [`PARSERS`] on every corpus it can decode.
//!
//! Each benchmark decodes a whole corpus and adds up its values. Results go
//! to one Criterion group per corpus; the crate's binary turns them into
//! tables.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use teltonika_comparison::{CORPUS_LEN, Corpus, PARSERS, group_name};

fn parsers(criterion: &mut Criterion) {
    for build in [Corpus::codec8, Corpus::mixed] {
        let corpus = build(CORPUS_LEN);
        let mut group = criterion.benchmark_group(group_name(&corpus));
        group.sample_size(10);
        group.throughput(Throughput::Bytes(corpus.bytes.len() as u64));
        for parser in PARSERS.iter().filter(|parser| parser.decodes(&corpus)) {
            group.bench_function(parser.id, |bench| {
                bench.iter(|| (parser.decode)(black_box(&corpus.bytes)))
            });
        }
        group.finish();
    }
}

criterion_group!(benches, parsers);
criterion_main!(benches);
