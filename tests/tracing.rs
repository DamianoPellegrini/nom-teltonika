#![cfg(feature = "tracing")]

mod common;

use std::{
    io,
    sync::{Arc, Mutex},
};

use common::*;
use nom_teltonika::decoder::{decode_tcp_frame, decode_udp_datagram};

struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn tracing_reports_structure_without_sensitive_wire_values() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&output);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || BufferWriter(Arc::clone(&writer_output)))
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        decode_tcp_frame(&bytes(CODEC12_COMMAND)).unwrap();
        decode_udp_datagram(&bytes(UDP_CODEC8)).unwrap();
    });

    let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(output.contains("outcome=\"accepted\""));
    assert!(output.contains("codec_id=12"));
    assert!(output.contains("transport=\"udp\""));
    for sensitive in ["getinfo", "352093086403655", "676574696E666F"] {
        assert!(!output.contains(sensitive), "tracing leaked {sensitive}");
    }
}
