//! Prints the results of `cargo bench -p teltonika-comparison` as Markdown
//! tables.
//!
//! The results are read from `target/criterion`, or from the directory
//! given as the first argument.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use teltonika_comparison::{BASELINE_ID, CORPUS_LEN, Corpus, PARSERS, Parser, group_name};

const MIB: f64 = 1024.0 * 1024.0;

fn main() -> ExitCode {
    let criterion = std::env::args_os().nth(1).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/criterion"),
        PathBuf::from,
    );
    for build in [Corpus::codec8, Corpus::mixed] {
        if let Err(error) = print_table(&criterion, &build(CORPUS_LEN)) {
            eprintln!("{error}");
            eprintln!("run `cargo bench -p teltonika-comparison` first");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// Prints the table of `corpus`, with one row for each parser.
fn print_table(criterion: &Path, corpus: &Corpus) -> Result<(), Box<dyn Error>> {
    let group = criterion.join(group_name(corpus));
    let baseline = median_seconds(&group, BASELINE_ID)?;

    println!(
        "{}: {:.0} MiB, {} frames, {} records.\n",
        corpus.description,
        corpus.bytes.len() as f64 / MIB,
        corpus.frames,
        corpus.records,
    );
    println!("| Parser | Output | Throughput | Records per second | Against 0.1.6 |");
    println!("| --- | --- | --- | --- | --- |");
    for parser in PARSERS.iter().filter(|parser| parser.decodes(corpus)) {
        let seconds = median_seconds(&group, parser.id)?;
        println!(
            "| {} | {} | {} | {:.1} million | {} |",
            parser.name,
            parser.output,
            throughput(corpus.bytes.len() as f64 / seconds),
            corpus.records as f64 / seconds / 1e6,
            ratio(parser, baseline / seconds),
        );
    }
    println!();
    Ok(())
}

/// Returns the median time in seconds that Criterion stored for
/// `parser_id` in `group`.
fn median_seconds(group: &Path, parser_id: &str) -> Result<f64, Box<dyn Error>> {
    let path = group.join(parser_id).join("new/estimates.json");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let estimates: serde_json::Value = serde_json::from_str(&text)?;
    let nanoseconds = estimates["median"]["point_estimate"]
        .as_f64()
        .ok_or_else(|| format!("{}: no median", path.display()))?;
    Ok(nanoseconds / 1e9)
}

fn throughput(bytes_per_second: f64) -> String {
    let mib = bytes_per_second / MIB;
    if mib >= 1024.0 {
        format!("{:.1} GiB/s", mib / 1024.0)
    } else {
        format!("{mib:.0} MiB/s")
    }
}

fn ratio(parser: &Parser, ratio: f64) -> String {
    if parser.id == BASELINE_ID {
        "1×".into()
    } else {
        format!("{ratio:.1}×")
    }
}
