//! A small blocking TCP server that handles each Teltonika device in a thread.
//!
//! Run with `cargo run --example tcp_server [-- ADDRESS]`; the address
//! defaults to `0.0.0.0:5000`, which macOS's AirPlay Receiver may already
//! hold.

use std::{
    error::Error,
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

use nom_teltonika::{
    protocol::{AvlPacketView, FrameView, Imei},
    tcp::{ReadFrameError, TeltonikaTcpStream},
};

const LISTEN_ADDRESS: &str = "0.0.0.0:5000";

type ServerError = Box<dyn Error + Send + Sync>;

fn main() -> Result<(), ServerError> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| LISTEN_ADDRESS.into());
    let listener = TcpListener::bind(&address)?;
    println!("listening on {address}");

    loop {
        match listener.accept() {
            Ok((socket, peer)) => {
                // Before spawning in production, enforce a connection limit, configure socket
                // timeouts, and retain thread handles so shutdown can wait for active sessions.
                thread::spawn(move || {
                    if let Err(error) = handle_connection(socket, peer) {
                        eprintln!("connection {peer} ended with an error: {error}");
                    }
                });
            }
            Err(error) => {
                // A real server should classify accept errors, add backoff, and emit metrics.
                eprintln!("failed to accept connection: {error}");
            }
        }
    }
}

fn handle_connection(socket: TcpStream, peer: SocketAddr) -> Result<(), ServerError> {
    let mut stream = TeltonikaTcpStream::new(socket);

    // The IMEI handshake comes before regular AVL or Codec 12 frames. Keep an
    // owned copy: the view borrows the stream only until the next read.
    let imei = stream.read_imei()?.evaluate();

    // Replace this with an allow-list or a call such as AuthService::is_allowed(imei).
    let accepted = is_device_allowed(&imei);
    stream.write_imei_approval(accepted)?;
    if !accepted {
        println!("rejected device from {peer}");
        return Ok(());
    }

    println!("accepted device from {peer}");
    let mut command_sent = false;

    loop {
        match stream.read_frame() {
            Ok(FrameView::Avl(packet)) => {
                let record_count = packet.records().len() as u32;

                // Acknowledge only after the records are durable. Replace this with, for
                // example, StorageService::persist(imei, packet.records()).
                if !persist_records(&imei, packet) {
                    stream.write_avl_nack()?;
                    eprintln!("could not persist {record_count} record(s) from {peer}");
                    continue;
                }

                stream.write_avl_ack(record_count)?;

                // Teltonika expects Codec 12 commands after AVL data has been acknowledged.
                if !command_sent {
                    stream.write_command("getinfo")?;
                    command_sent = true;
                }
            }
            Ok(FrameView::Gprs(packet)) => {
                // In production, correlate responses with queued commands and avoid logging
                // payloads that may contain sensitive device information.
                for message in packet.messages() {
                    println!(
                        "Codec 12 {:?} from {peer}: {}",
                        message.kind(),
                        String::from_utf8_lossy(message.payload())
                    );
                }
            }
            Ok(_) => {
                // FrameView is non-exhaustive so newer library versions can add codecs.
                eprintln!("unsupported frame from {peer}");
            }
            Err(ReadFrameError::Closed) => {
                println!("device at {peer} disconnected");
                return Ok(());
            }
            Err(error @ ReadFrameError::InvalidFrame(_)) => {
                // The invalid frame is already consumed: ask the device to send it again.
                eprintln!("invalid frame from {peer}: {error}");
                stream.write_avl_nack()?;
            }
            Err(error) => {
                // Truncated frames, invalid headers, and I/O failures end this device session.
                return Err(error.into());
            }
        }
    }
}

fn is_device_allowed(imei: &Imei) -> bool {
    let _ = imei;
    true
}

fn persist_records(imei: &Imei, packet: AvlPacketView<'_>) -> bool {
    println!(
        "received {} AVL record(s) from {imei}",
        packet.records().len()
    );
    true
}
