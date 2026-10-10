#![cfg(feature = "tracing")]

mod common;

use std::{
    io::{self, Cursor},
    net::UdpSocket,
    sync::{Arc, Mutex},
    time::Duration,
};

use common::*;
use nom_teltonika::{tcp::TeltonikaTcpStream, udp::TeltonikaUdpSocket};

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
fn tracing_reports_structure_without_sensitive_values() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&output);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || BufferWriter(Arc::clone(&writer_output)))
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let mut input = bytes("000F333536333037303432343431303133");
        input.extend_from_slice(&bytes(CODEC12_COMMAND));
        let mut stream = TeltonikaTcpStream::new(Cursor::new(input));
        stream.read_imei().unwrap();
        stream.read_frame().unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let mut server = TeltonikaUdpSocket::new(server);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(&bytes(UDP_CODEC8), address).unwrap();
        server.receive_datagram().unwrap();
    });

    let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(output.contains("read IMEI handshake"));
    assert!(output.contains("read TCP frame"));
    assert!(output.contains("codec_id=12"));
    assert!(output.contains("received UDP datagram"));
    for sensitive in [
        "getinfo",
        "356307042441013",
        "352093086403655",
        "676574696E666F",
    ] {
        assert!(!output.contains(sensitive), "tracing leaked {sensitive}");
    }
}
