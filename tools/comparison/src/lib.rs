//! Benchmarks of `nom-teltonika` against other Teltonika parsers and its own
//! 0.1.6 release.
//!
//! Every parser gets the same job on the same bytes: decode frames sent back
//! to back, as a TCP connection delivers them, and add up what they hold
//! into [`Totals`]. A parser is one entry of [`PARSERS`]: a function from the
//! bytes to the totals, written against that parser's own API. The totals
//! make the parsers comparable in two ways: the tests check that all of them
//! found the same values, and a parser can't skip a field that ends up in a
//! sum.
//!
//! The bytes come from a [`Corpus`], built from the simulator's vehicles, so
//! records carry what an FMB003 sends. Two of the parsers compared decode
//! Codec 8 only, and one holds at most 4 records per packet: the Codec 8
//! corpus stays within both limits, and the mixed one is decoded by the
//! parsers that can.
//!
//! To compare another parser, add its function and its entry to
//! [`PARSERS`]: the benchmark, the tests, and the report pick it up.
//!
//! ```sh
//! cargo bench -p teltonika-comparison
//! cargo run --release -p teltonika-comparison
//! ```
//!
//! The first command measures; the second prints the results as Markdown
//! tables, from what Criterion stored.

mod corpus;
mod parsers;

pub use corpus::Corpus;
pub use parsers::{BASELINE_ID, PARSERS, Parser, Totals};

/// Bytes of traffic in a benchmarked corpus: more than any cache holds, so
/// the result is what a server sustains.
pub const CORPUS_LEN: usize = 64 * 1024 * 1024;

/// Returns the Criterion group of `corpus`, which is also its directory
/// under `target/criterion`.
pub fn group_name(corpus: &Corpus) -> String {
    format!("comparison_{}", corpus.name)
}
