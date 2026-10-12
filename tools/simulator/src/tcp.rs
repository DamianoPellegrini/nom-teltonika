use std::time::Duration;

use nom_teltonika::decoder::{DecodeFrameError, take_frame};
use nom_teltonika::encoder::encode_gprs_frame;
use nom_teltonika::protocol::{FrameView, GprsMessageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, sleep_until, timeout};

use crate::commands::{DeviceState, answer};
use crate::fault::{break_crc, break_tcp_count};
use crate::run::{Device, now_millis};
use crate::traffic::{Packet, Traffic};
use crate::{Fault, Report, RunConfig};

/// How long a lone `00 00 00 00` waits for more bytes before it is read as
/// a negative acknowledgment rather than the start of a Codec 12 frame.
const NACK_GRACE: Duration = Duration::from_millis(50);

/// Delay between bytes of a [`Fault::Slow`] write.
const SLOW_BYTE_DELAY: Duration = Duration::from_millis(1);

/// An open, approved TCP session with its unread bytes.
struct Session {
    stream: TcpStream,
    buffer: Vec<u8>,
}

/// Why a session can't go on.
enum Broken {
    /// The server closed the connection or I/O failed.
    Closed,
    /// No acknowledgment arrived in time.
    Timeout,
}

/// Runs one TCP device to the end and returns its report.
///
/// As a device does, it keeps a packet until the server acknowledges all of
/// its records: after a negative acknowledgment, a timeout, or a lost
/// connection, it sends the same records again.
pub(crate) async fn run_device(config: &RunConfig, mut device: Device) -> Report {
    let mut traffic = device.traffic(config);
    let mut rng = fastrand::Rng::with_seed(device.seed ^ 0x5eed_fa17);
    let mut session: Option<Session> = None;
    let mut unacknowledged: Option<Packet> = None;
    let mut next_send = Instant::now() + config.interval;

    while !device.done(config) {
        let mut open = match session.take() {
            Some(open) => open,
            None => match connect(config, &mut device).await {
                Some(open) => open,
                // Refused or unreachable: retrying would only repeat it.
                None => break,
            },
        };
        let idled = {
            let Device {
                imei,
                mac,
                init_millis,
                report,
                ..
            } = &mut device;
            let state = state(imei, *mac, *init_millis, report.records_acked, &traffic);
            idle(&mut open, next_send, report, &state).await
        };
        if idled.is_err() {
            device.report.errors += 1;
            continue;
        }

        let packet = match unacknowledged.take() {
            Some(packet) => {
                device.report.resent += 1;
                packet
            }
            None => {
                next_send = Instant::now() + config.interval;
                match traffic.next_frame() {
                    Ok(packet) => packet,
                    Err(_) => {
                        device.report.errors += 1;
                        break;
                    }
                }
            }
        };
        let records = u64::from(packet.records);
        let fault = config.faults.pick(&mut rng);
        device.report.packets += 1;
        device.report.records += records;
        if fault.is_some() {
            device.report.faults += 1;
        }

        let mut bytes = packet.bytes.clone();
        match fault {
            Some(Fault::Disconnect) => {
                drop(open);
                match connect(config, &mut device).await {
                    Some(reopened) => open = reopened,
                    None => break,
                }
            }
            Some(Fault::BadCrc) => break_crc(&mut bytes),
            Some(Fault::WrongCount) => break_tcp_count(&mut bytes),
            Some(Fault::Truncate) => {
                // Half a frame, then close: the server can't acknowledge it.
                let _ = open.stream.write_all(&bytes[..bytes.len() / 2]).await;
                let _ = open.stream.shutdown().await;
                device.report.expected_drops += 1;
                unacknowledged = Some(packet);
                continue;
            }
            Some(Fault::Slow) | None => {}
        }

        let written = if fault == Some(Fault::Slow) {
            write_slowly(&mut open.stream, &bytes).await
        } else {
            open.stream.write_all(&bytes).await
        };
        if written.is_err() {
            device.report.errors += 1;
            unacknowledged = Some(packet);
            continue;
        }

        let sent_at = Instant::now();
        let rejected_on_purpose = matches!(fault, Some(Fault::BadCrc | Fault::WrongCount));
        let acknowledgment = {
            let Device {
                imei,
                mac,
                init_millis,
                report,
                ..
            } = &mut device;
            let state = state(imei, *mac, *init_millis, report.records_acked, &traffic);
            read_ack(&mut open, config.ack_timeout, report, &state).await
        };
        match acknowledgment {
            Ok(acked) => {
                if acked != 0 {
                    // A NACK's time includes the wait that tells it apart
                    // from a command, so only positive acknowledgments count.
                    device.report.ack_latencies.push(sent_at.elapsed());
                }
                match (acked, rejected_on_purpose) {
                    (0, true) => {
                        device.report.expected_nacks += 1;
                        unacknowledged = Some(packet);
                    }
                    (acked, false) if u64::from(acked) == records => {
                        device.report.records_acked += records;
                    }
                    _ => {
                        device.report.ack_mismatches += 1;
                        unacknowledged = Some(packet);
                    }
                }
                session = Some(open);
            }
            Err(broken) => {
                match broken {
                    Broken::Timeout => device.report.timeouts += 1,
                    Broken::Closed => device.report.errors += 1,
                }
                unacknowledged = Some(packet);
            }
        }
    }
    device.report
}

/// Returns what the device reports about itself, for command answers.
fn state<'a>(
    imei: &'a str,
    mac: [u8; 6],
    init_millis: u64,
    sent_records: u64,
    traffic: &'a Traffic,
) -> DeviceState<'a> {
    DeviceState {
        imei,
        mac,
        init_millis,
        now_millis: now_millis(),
        sent_records,
        traffic,
    }
}

/// Connects, sends the IMEI handshake, and reads the approval.
///
/// Returns `None`, and counts why, if the server can't be reached or
/// refuses the IMEI.
async fn connect(config: &RunConfig, device: &mut Device) -> Option<Session> {
    let report = &mut device.report;
    let Ok(mut stream) = TcpStream::connect(config.server).await else {
        report.errors += 1;
        return None;
    };
    let _ = stream.set_nodelay(true);
    report.connections += 1;

    // "First comes a short identifying the number of bytes written and then
    // goes IMEI as text" (Data Sending Protocols, "Codec 8 > Communication
    // with server").
    let imei = device.imei.as_bytes();
    let mut handshake = Vec::with_capacity(2 + imei.len());
    handshake.extend_from_slice(&(imei.len() as u16).to_be_bytes());
    handshake.extend_from_slice(imei);
    let mut approval = [0];
    let exchange = async {
        stream.write_all(&handshake).await?;
        stream.read_exact(&mut approval).await
    };
    match timeout(config.ack_timeout, exchange).await {
        Ok(Ok(_)) if approval == [1] => Some(Session {
            stream,
            buffer: Vec::new(),
        }),
        Ok(Ok(_)) => {
            report.rejected_imeis += 1;
            None
        }
        _ => {
            report.errors += 1;
            None
        }
    }
}

/// Writes `frame` one byte at a time.
async fn write_slowly(stream: &mut TcpStream, frame: &[u8]) -> std::io::Result<()> {
    for byte in frame {
        stream.write_all(std::slice::from_ref(byte)).await?;
        sleep(SLOW_BYTE_DELAY).await;
    }
    Ok(())
}

/// Waits until `until`, answering the Codec 12 commands that arrive
/// meanwhile.
async fn idle(
    session: &mut Session,
    until: Instant,
    report: &mut Report,
    state: &DeviceState<'_>,
) -> Result<(), Broken> {
    loop {
        answer_commands(session, report, state).await?;
        if !session.buffer.is_empty() && !starts_frame(&session.buffer) {
            // Only commands arrive between packets.
            report.errors += 1;
            session.buffer.clear();
        }
        tokio::select! {
            () = sleep_until(until) => return Ok(()),
            read = session.stream.read_buf(&mut session.buffer) => match read {
                Ok(0) | Err(_) => return Err(Broken::Closed),
                Ok(_) => {}
            },
        }
    }
}

/// Reads the acknowledgment of the packet just sent: the number of records
/// the server accepted, 0 for a negative acknowledgment.
///
/// Commands the server sent before it are answered first. A NACK and a
/// command frame both start with four zero bytes; a command then declares
/// a non-zero data length, so the four bytes after them decide.
async fn read_ack(
    session: &mut Session,
    wait: Duration,
    report: &mut Report,
    state: &DeviceState<'_>,
) -> Result<u32, Broken> {
    let deadline = Instant::now() + wait;
    loop {
        answer_commands(session, report, state).await?;
        let buffer = &session.buffer;
        match (buffer.first_chunk::<4>(), buffer.len()) {
            // A non-zero count: an acknowledgment.
            (Some(&count), _) if count != [0; 4] => {
                session.buffer.drain(..4);
                return Ok(u32::from_be_bytes(count));
            }
            // Four zero bytes and a zero length: a NACK, then the next
            // frame's preamble.
            (Some(_), 8..) if !starts_frame(buffer) => {
                session.buffer.drain(..4);
                return Ok(0);
            }
            // Four zero bytes alone: a NACK, unless a frame follows.
            (Some(_), ..8) => {
                let grace = deadline.min(Instant::now() + NACK_GRACE);
                match timeout_at(grace, session).await {
                    Ok(()) => {}
                    Err(Broken::Timeout) => {
                        session.buffer.drain(..4);
                        return Ok(0);
                    }
                    Err(broken) => return Err(broken),
                }
            }
            // Fewer than four bytes, or a command frame not fully buffered.
            _ => timeout_at(deadline, session).await?,
        }
    }
}

/// Reads more bytes into the session buffer, until `deadline`.
async fn timeout_at(deadline: Instant, session: &mut Session) -> Result<(), Broken> {
    match tokio::time::timeout_at(deadline, session.stream.read_buf(&mut session.buffer)).await {
        Ok(Ok(0) | Err(_)) => Err(Broken::Closed),
        Ok(Ok(_)) => Ok(()),
        Err(_) => Err(Broken::Timeout),
    }
}

/// Returns `true` if `buffer` starts like a frame: four zero bytes, then,
/// if buffered, a non-zero data length.
fn starts_frame(buffer: &[u8]) -> bool {
    let preamble = buffer.iter().take(4).all(|&byte| byte == 0);
    let length = buffer.get(4..8).is_none_or(|length| length != [0; 4]);
    preamble && length
}

/// Answers every complete Codec 12 frame at the head of the buffer.
///
/// Each known command gets one response in the device's words; unknown
/// commands get none. Anything else that decodes, or fails to, counts as an
/// error and is dropped.
async fn answer_commands(
    session: &mut Session,
    report: &mut Report,
    state: &DeviceState<'_>,
) -> Result<(), Broken> {
    while session.buffer.len() >= 8 && starts_frame(&session.buffer) {
        let mut input = &session.buffer[..];
        let responses: Vec<String> = match take_frame(&mut input) {
            Ok(FrameView::Gprs(packet)) => {
                report.commands += packet.messages().len() as u64;
                packet
                    .messages()
                    .filter(|message| message.kind() == GprsMessageType::Command)
                    .filter_map(|message| answer(message.payload(), state))
                    .collect()
            }
            Err(DecodeFrameError::Incomplete { .. }) => return Ok(()),
            Err(DecodeFrameError::InvalidHeader(_)) => {
                report.errors += 1;
                session.buffer.clear();
                return Ok(());
            }
            Ok(_) | Err(DecodeFrameError::InvalidFrame { .. }) => {
                report.errors += 1;
                Vec::new()
            }
        };
        let consumed = session.buffer.len() - input.len();
        session.buffer.drain(..consumed);
        if responses.is_empty() {
            continue;
        }
        let Ok(frame) = encode_gprs_frame(GprsMessageType::Response, &responses) else {
            report.errors += 1;
            continue;
        };
        if session.stream.write_all(&frame).await.is_err() {
            return Err(Broken::Closed);
        }
        report.commands_answered += responses.len() as u64;
    }
    Ok(())
}
