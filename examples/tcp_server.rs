//! A small blocking TCP server that handles each Teltonika device in a thread.
//!
//! Run with `cargo run --example tcp_server`.

use std::{
    error::Error,
    io::Read,
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

use nom_teltonika::{
    decoder::{DecodeError, decode_imei},
    protocol::{AvlPacket, Frame, Imei},
    stream::{StreamReadError, TeltonikaTcpStream},
};

const LISTEN_ADDRESS: &str = "0.0.0.0:5000";
const IMEI_FRAME_BYTES: usize = 17;

type ServerError = Box<dyn Error + Send + Sync>;

fn main() -> Result<(), ServerError> {
    let listener = TcpListener::bind(LISTEN_ADDRESS)?;
    println!("listening on {LISTEN_ADDRESS}");

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

fn handle_connection(mut socket: TcpStream, peer: SocketAddr) -> Result<(), ServerError> {
    // The IMEI handshake comes before regular AVL or Codec 12 frames.
    let mut handshake = [0_u8; IMEI_FRAME_BYTES];
    socket.read_exact(&mut handshake)?;
    let imei = decode_imei(&handshake)?.value;

    // Replace this with an allow-list or a call such as AuthService::is_allowed(imei).
    let accepted = is_device_allowed(imei);
    let mut stream = TeltonikaTcpStream::new(socket);
    stream.write_imei_approval(accepted)?;
    if !accepted {
        println!("rejected device from {peer}");
        return Ok(());
    }

    println!("accepted device from {peer}");
    let mut command_sent = false;

    loop {
        match stream.read_frame() {
            Ok(Frame::Avl(packet)) => {
                let record_count = packet.records().len() as u32;

                // Acknowledge only after the records are durable. Replace this with, for
                // example, StorageService::persist(imei, packet.records()).
                if !persist_records(imei, &packet) {
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
            Ok(Frame::Codec12(packet)) => {
                // In production, correlate responses with queued commands and avoid logging
                // payloads that may contain sensitive device information.
                println!("Codec 12 message from {peer}: {:?}", packet.message());
            }
            Ok(_) => {
                // Frame is non-exhaustive so newer library versions can add codecs.
                eprintln!("unsupported frame from {peer}");
            }
            Err(StreamReadError::Closed) => {
                println!("device at {peer} disconnected");
                return Ok(());
            }
            Err(error @ StreamReadError::Decode(DecodeError::Rejected { .. })) => {
                // Rejected, delimited frames are already consumed. Decide here whether your
                // device policy should continue, disconnect, or send a protocol-specific NACK.
                eprintln!("rejected frame from {peer}: {error}");
            }
            Err(error) => {
                // Truncated frames, fatal framing, and I/O failures end this device session.
                return Err(error.into());
            }
        }
    }
}

fn is_device_allowed(imei: Imei) -> bool {
    let _ = imei;
    true
}

fn persist_records(imei: Imei, packet: &AvlPacket) -> bool {
    let _ = imei;
    println!("received {} AVL record(s)", packet.records().len());
    true
}
