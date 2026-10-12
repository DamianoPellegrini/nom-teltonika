use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use nom_teltonika::protocol::ImeiView;
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::fault::break_udp_count;
use crate::run::Device;
use crate::traffic::Packet;
use crate::{Fault, Report, RunConfig};

/// Runs one UDP device to the end and returns its report.
///
/// As a device does, it sends a datagram again, unchanged, until the server
/// acknowledges all of its records. Over UDP only [`Fault::WrongCount`] and
/// [`Fault::Truncate`] apply; the other faults are never picked. A faulty
/// datagram expects no acknowledgment, so the device doesn't wait for one.
pub(crate) async fn run_device(config: &RunConfig, mut device: Device) -> Report {
    let local: SocketAddr = match config.server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match UdpSocket::bind(local).await {
        Ok(socket) if socket.connect(config.server).await.is_ok() => socket,
        _ => {
            device.report.errors += 1;
            return device.report;
        }
    };
    device.report.connections += 1;

    let imei = ImeiView::try_from(device.imei.as_str()).expect("the IMEI is 15 digits");
    let mut traffic = device.traffic(config);
    let mut rng = fastrand::Rng::with_seed(device.seed ^ 0x5eed_fa17);
    let mut packet_id = rng.u16(..);
    let mut avl_packet_id = rng.u8(..);
    // The datagram waiting for its acknowledgment, with its IDs.
    let mut unacknowledged: Option<(Packet, u16, u8)> = None;
    let mut next_send = Instant::now() + config.interval;

    while !device.done(config) {
        sleep_until(next_send).await;
        let (packet, sent_packet_id, sent_avl_id) = match unacknowledged.take() {
            Some(pending) => {
                device.report.resent += 1;
                pending
            }
            None => {
                packet_id = packet_id.wrapping_add(1);
                avl_packet_id = avl_packet_id.wrapping_add(1);
                match traffic.next_datagram(packet_id, avl_packet_id, imei) {
                    Ok(packet) => (packet, packet_id, avl_packet_id),
                    Err(_) => {
                        device.report.errors += 1;
                        break;
                    }
                }
            }
        };
        next_send = Instant::now() + config.interval;
        let records = u64::from(packet.records);
        let fault = config
            .faults
            .pick(&mut rng)
            .filter(|fault| matches!(fault, Fault::WrongCount | Fault::Truncate));
        device.report.packets += 1;
        device.report.records += records;

        let mut bytes = packet.bytes.clone();
        match fault {
            Some(Fault::WrongCount) => break_udp_count(&mut bytes),
            Some(_) => bytes.truncate(bytes.len() / 2),
            None => {}
        }
        if socket.send(&bytes).await.is_err() {
            device.report.errors += 1;
            unacknowledged = Some((packet, sent_packet_id, sent_avl_id));
            continue;
        }
        if fault.is_some() {
            device.report.faults += 1;
            device.report.expected_drops += 1;
            unacknowledged = Some((packet, sent_packet_id, sent_avl_id));
            continue;
        }

        let sent_at = Instant::now();
        let deadline = sent_at + config.ack_timeout;
        let mut ack = [0; 16];
        let acknowledged = loop {
            match timeout_at(deadline, socket.recv(&mut ack)).await {
                Err(_) => {
                    device.report.timeouts += 1;
                    break false;
                }
                Ok(Err(_)) => {
                    device.report.errors += 1;
                    break false;
                }
                Ok(Ok(len)) => {
                    // "0005 | packet ID | 01 | AVL packet ID | accepted"
                    // (Codec wiki, "Codec8 protocol sending over UDP").
                    let [0x00, 0x05, high, low, 0x01, avl_id, accepted] = ack[..len] else {
                        device.report.ack_mismatches += 1;
                        break false;
                    };
                    if avl_id != sent_avl_id {
                        // A late acknowledgment of an earlier datagram.
                        continue;
                    }
                    if u16::from_be_bytes([high, low]) != sent_packet_id {
                        // The AVL packet ID matches, but the packet ID isn't
                        // echoed, as the wiki requires.
                        device.report.ack_mismatches += 1;
                        break false;
                    }
                    device.report.ack_latencies.push(sent_at.elapsed());
                    if u64::from(accepted) == records {
                        device.report.records_acked += records;
                        break true;
                    }
                    device.report.ack_mismatches += 1;
                    break false;
                }
            }
        };
        if !acknowledged {
            unacknowledged = Some((packet, sent_packet_id, sent_avl_id));
        }
    }
    device.report
}
