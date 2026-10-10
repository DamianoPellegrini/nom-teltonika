#![cfg(feature = "std")]

mod common;

use std::{net::UdpSocket, time::Duration};

use common::*;
use nom_teltonika::{
    decoder::DatagramError,
    udp::{ReceiveDatagramError, TeltonikaUdpSocket},
};

fn bind() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

#[test]
fn should_serve_multiple_udp_peers_and_ack_explicit_destinations() {
    let server_socket = bind();
    let server_address = server_socket.local_addr().unwrap();
    let mut server = TeltonikaUdpSocket::new(server_socket);
    let first = bind();
    let second = bind();
    let datagram = bytes(UDP_CODEC8);

    for peer in [&first, &second] {
        peer.send_to(&datagram, server_address).unwrap();
        let (received, source) = server.receive_datagram().unwrap();
        assert_eq!(source, peer.local_addr().unwrap());
        let ids = received.ids();
        let accepted = received.packet().records().len() as u8;
        server.send_ack_to(source, ids, accepted).unwrap();
    }

    // "Codec 8 > Codec8 protocol sending over UDP > Example": the server
    // responds `0005CAFE010501`.
    for peer in [&first, &second] {
        let mut acknowledgment = [0; 7];
        peer.recv(&mut acknowledgment).unwrap();
        assert_eq!(acknowledgment, [0x00, 0x05, 0xca, 0xfe, 0x01, 0x05, 0x01]);
    }
}

#[test]
fn should_drop_an_invalid_datagram_and_receive_the_next() {
    let server_socket = bind();
    let server_address = server_socket.local_addr().unwrap();
    let mut server = TeltonikaUdpSocket::new(server_socket);
    let client = bind();

    client.send_to(&[0; 57], server_address).unwrap();
    client.send_to(&bytes(UDP_CODEC8), server_address).unwrap();
    assert!(matches!(
        server.receive_datagram(),
        Err(ReceiveDatagramError::InvalidDatagram {
            peer,
            reason: DatagramError::LengthMismatch {
                declared: 0,
                actual: 55
            },
            ..
        }) if peer == client.local_addr().unwrap()
    ));
    assert!(server.receive_datagram().is_ok());
}
