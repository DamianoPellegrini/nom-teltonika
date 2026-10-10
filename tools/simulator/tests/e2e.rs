//! Simulated devices against in-process servers built on `nom-teltonika`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nom_teltonika::protocol::{AvlCodec, FrameView, GprsMessageType};
use nom_teltonika::tcp::{ReadFrameError, TeltonikaTcpStream};
use nom_teltonika::udp::TeltonikaUdpSocket;
use teltonika_simulator::{Fault, Faults, Report, RunConfig, Stop, Transport, run};
use tokio::net::{TcpListener, UdpSocket};

/// Responses the TCP server received to its commands.
#[derive(Debug, Default)]
struct Seen {
    responses: AtomicU64,
}

/// Starts a TCP server that approves every IMEI, acknowledges every valid
/// packet, NACKs invalid frames, and sends `getinfo` after the first
/// acknowledgment of each connection.
async fn tcp_server() -> (SocketAddr, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let server_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let seen = Arc::clone(&server_seen);
            tokio::spawn(async move {
                let mut stream = TeltonikaTcpStream::new(socket);
                if stream.read_imei_async().await.is_err() {
                    return;
                }
                stream.write_imei_approval_async(true).await.unwrap();
                let mut command_sent = false;
                loop {
                    match stream.read_frame_async().await {
                        Ok(FrameView::Avl(packet)) => {
                            let records = packet.records().len() as u32;
                            stream.write_avl_ack_async(records).await.unwrap();
                            if !command_sent {
                                stream.write_command_async("getinfo").await.unwrap();
                                command_sent = true;
                            }
                        }
                        Ok(FrameView::Gprs(packet)) => {
                            for message in packet.messages() {
                                assert_eq!(message.kind(), GprsMessageType::Response);
                                assert!(message.payload().starts_with(b"RTC:"));
                                seen.responses.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Ok(_) => unreachable!("only AVL and GPRS frames exist"),
                        Err(ReadFrameError::InvalidFrame(_)) => {
                            stream.write_avl_nack_async().await.unwrap();
                        }
                        // Closed, truncated on purpose, or reset.
                        Err(_) => return,
                    }
                }
            });
        }
    });
    (address, seen)
}

/// Starts a UDP server that acknowledges every valid datagram with packet ID
/// 0 instead of the datagram's, as Traccar does.
async fn udp_server_without_packet_ids() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0; 2048];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let Ok(datagram) = nom_teltonika::decoder::take_datagram(&mut &buffer[..len]) else {
                continue;
            };
            let accepted = datagram.packet().records().len() as u8;
            let ack = [
                0x00,
                0x05,
                0x00,
                0x00,
                0x01,
                datagram.avl_packet_id(),
                accepted,
            ];
            socket.send_to(&ack, peer).await.unwrap();
        }
    });
    address
}

/// Starts a UDP server that acknowledges every valid datagram.
async fn udp_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut socket = TeltonikaUdpSocket::new(socket);
    tokio::spawn(async move {
        loop {
            let (ids, accepted, peer) = match socket.receive_datagram_async().await {
                Ok((datagram, peer)) => (
                    datagram.ids(),
                    datagram.packet().records().len() as u8,
                    peer,
                ),
                // Invalid datagrams are dropped without acknowledgment.
                Err(_) => continue,
            };
            socket.send_ack_to_async(peer, ids, accepted).await.unwrap();
        }
    });
    address
}

fn config(server: SocketAddr, transport: Transport, codec: AvlCodec) -> RunConfig {
    RunConfig {
        server,
        transport,
        devices: 4,
        codec,
        records_per_packet: 3,
        interval: Duration::ZERO,
        stop: Stop::Packets(20),
        seed: 1,
        tac: 35_630_704,
        faults: Faults::none(),
        ack_timeout: Duration::from_secs(5),
        ramp_up: Duration::ZERO,
    }
}

fn assert_clean(report: &Report) {
    assert_eq!(report.unexpected(), 0, "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_devices_are_acknowledged_and_answer_commands() {
    for codec in [
        AvlCodec::Codec8,
        AvlCodec::Codec8Extended,
        AvlCodec::Codec16,
    ] {
        let (server, seen) = tcp_server().await;
        let report = run(config(server, Transport::Tcp, codec)).await;

        assert_clean(&report);
        assert_eq!(report.devices, 4);
        assert_eq!(report.connections, 4);
        assert_eq!(report.packets, 4 * 20);
        assert_eq!(report.records_acked, report.records);
        assert_eq!(report.resent, 0);
        assert_eq!(report.commands_answered, 4);
        assert_eq!(report.ack_latencies.len(), 4 * 20);
        // The last responses may still be in flight when the devices stop.
        assert!(seen.responses.load(Ordering::Relaxed) <= 4);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_faults_get_the_expected_reactions() {
    let (server, _) = tcp_server().await;
    let mut config = config(server, Transport::Tcp, AvlCodec::Codec8Extended);
    config.faults = Faults::new(vec![Fault::BadCrc, Fault::WrongCount], 1.0);
    let report = run(config).await;

    assert_clean(&report);
    assert_eq!(report.faults, 4 * 20);
    assert_eq!(report.expected_nacks, 4 * 20);
    assert_eq!(report.records_acked, 0);
    // Every rejected packet is sent again: all but each device's first.
    assert_eq!(report.resent, 4 * 19);
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_devices_recover_from_disconnects_truncation_and_slow_writes() {
    let (server, _) = tcp_server().await;
    let mut config = config(server, Transport::Tcp, AvlCodec::Codec8);
    config.devices = 2;
    config.stop = Stop::Packets(30);
    config.faults = Faults::new(vec![Fault::Disconnect, Fault::Truncate, Fault::Slow], 0.5);
    let report = run(config).await;

    assert_clean(&report);
    assert!(report.faults > 0);
    assert!(report.connections > 2, "{report}");
    // Every truncated packet is sent again, and every other one acknowledged.
    assert_eq!(report.resent, report.expected_drops, "{report}");
    assert_eq!(
        report.packets - report.expected_drops,
        report.ack_latencies.len() as u64,
        "{report}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_devices_are_acknowledged_and_faults_dropped() {
    let server = udp_server().await;
    let report = run(config(server, Transport::Udp, AvlCodec::Codec16)).await;
    assert_clean(&report);
    assert_eq!(report.records_acked, report.records);

    let mut faulty = config(server, Transport::Udp, AvlCodec::Codec8);
    faulty.faults = Faults::new(vec![Fault::WrongCount, Fault::Truncate], 1.0);
    let report = run(faulty).await;
    assert_clean(&report);
    assert_eq!(report.expected_drops, 4 * 20);
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_acks_without_the_packet_id_are_mismatches() {
    let server = udp_server_without_packet_ids().await;
    let report = run(config(server, Transport::Udp, AvlCodec::Codec8)).await;
    assert_eq!(report.ack_mismatches, 4 * 20, "{report}");
    // The device keeps sending the datagram the server never acknowledged.
    assert_eq!(report.resent, 4 * 19, "{report}");
    assert_eq!(report.timeouts, 0, "{report}");
}

#[test]
fn imeis_have_a_valid_check_digit() {
    // The IMEI of the Teltonika wiki's examples.
    assert_eq!(
        teltonika_simulator::imei(35_630_704, 244_101),
        "356307042441013"
    );
    assert_eq!(teltonika_simulator::imei(35_630_704, 0), "356307040000001");
}
