mod common;

use std::{net::UdpSocket, time::Duration};

use common::*;
use nom_teltonika::{
    encode::encode_udp_ack,
    parser::Limits,
    udp::{TeltonikaUdpSocket, UdpSocketError},
};

#[test]
fn should_serve_multiple_udp_peers_and_ack_explicit_destinations() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server_address = server_socket.local_addr().unwrap();
    let mut server = TeltonikaUdpSocket::new(server_socket);
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let datagram = bytes(UDP_CODEC8);

    for peer in [&first, &second] {
        peer.send_to(&datagram, server_address).unwrap();
        let (received, source) = server.recv_datagram().unwrap();
        assert_eq!(source, peer.local_addr().unwrap());
        server
            .send_ack_to(
                source,
                received.channel_packet_id(),
                received.avl_packet_id(),
                1,
            )
            .unwrap();
    }

    let mut acknowledgment = [0; 7];
    first.recv(&mut acknowledgment).unwrap();
    assert_eq!(acknowledgment, encode_udp_ack(0xcafe, 5, 1));
    second.recv(&mut acknowledgment).unwrap();
    assert_eq!(acknowledgment, encode_udp_ack(0xcafe, 5, 1));
}

#[test]
fn should_detect_udp_socket_truncation_without_parsing_prefix() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server_address = server_socket.local_addr().unwrap();
    let limits = Limits::new(1280, 65_536, 23).unwrap();
    let mut server = TeltonikaUdpSocket::with_limits(server_socket, limits);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(&[0; 24], server_address).unwrap();
    assert!(matches!(
        server.recv_datagram(),
        Err(UdpSocketError::Truncated {
            received_at_least: 24,
            limit: 23
        })
    ));
}
