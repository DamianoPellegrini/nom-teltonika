//! Benchmarks of `nom-teltonika` against its 0.1.6 release and other
//! Teltonika parsers.
//!
//! Each parser in [`PARSERS`] decodes the same frames and sums the values it
//! reads into [`Totals`]. The tests check that every parser returns the same
//! totals.
//!
//! The frames come from a [`Corpus`], built with the simulator.
//! `teltonika-rs` and `teltonika-avl-protocol` decode Codec 8 only, so they
//! run on the Codec 8 corpus alone.
//!
//! To compare another parser, add an entry to [`PARSERS`].
//!
//! # Running
//!
//! ```sh
//! cargo bench -p teltonika-comparison
//! cargo run --release -p teltonika-comparison
//! ```
//!
//! The second command prints the results as Markdown tables.

mod corpus;
mod parsers;

pub use corpus::Corpus;
pub use parsers::{BASELINE_ID, PARSERS, Parser, Totals};

/// The length in bytes of a benchmarked corpus.
///
/// It is larger than the CPU caches.
pub const CORPUS_LEN: usize = 64 * 1024 * 1024;

/// Returns the name of the Criterion group of `corpus`.
///
/// Criterion stores the results in a directory of this name.
pub fn group_name(corpus: &Corpus) -> String {
    format!("comparison_{}", corpus.name)
}
