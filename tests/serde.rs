#![cfg(feature = "serde")]
use std::{
    fs::File,
    io::{BufWriter, Read},
};

use nom_teltonika::*;

#[test]
fn parse_file() {
    // Load test.bin
    let mut file = File::open("tests/test.bin").expect("Can't open bin file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Can't read bin file");
    // Parse test.bin
    let (_, frame) = parser::tcp_frame(&buffer).expect("Can't parse frame");
    let writer = BufWriter::new(File::create("tests/test.json").expect("Can't create json file"));
    serde_json::to_writer_pretty(writer, &frame).expect("Can't serialize frame to json");
}
