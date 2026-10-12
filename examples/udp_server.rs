//! A small blocking UDP server: one socket for every Teltonika device.
//!
//! Run with `cargo run --example udp_server [-- ADDRESS]`; the address
//! defaults to `0.0.0.0:5001`.

use std::{error::Error, net::UdpSocket};

use nom_teltonika::udp::{ReceiveDatagramError, TeltonikaUdpSocket};

const LISTEN_ADDRESS: &str = "0.0.0.0:5001";

fn main() -> Result<(), Box<dyn Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| LISTEN_ADDRESS.into());
    let mut socket = TeltonikaUdpSocket::new(UdpSocket::bind(&address)?);
    println!("listening on {address}");

    loop {
        match socket.receive_datagram() {
            Ok((datagram, peer)) => {
                // Copy what the acknowledgment needs: the datagram borrows the socket.
                let ids = datagram.ids();
                let accepted = datagram.packet().records().len() as u8;
                println!(
                    "received {accepted} AVL record(s) from {} at {peer}",
                    datagram.imei()
                );
                // Acknowledge only after the records are durable.
                socket.send_ack_to(peer, ids, accepted)?;
            }
            Err(ReceiveDatagramError::InvalidDatagram { peer, ids, reason }) => {
                eprintln!("invalid datagram from {peer}: {reason}");
                // Without an answer, the device sends the datagram again after
                // its timeout. Acknowledging zero records asks for it at once.
                socket.send_ack_to(peer, ids, 0)?;
            }
            Err(error @ ReceiveDatagramError::NoHeader { .. }) => {
                // Too short to have IDs: there is nothing to answer with.
                eprintln!("{error}");
            }
            Err(error) => return Err(error.into()),
        }
    }
}
