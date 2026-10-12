use std::fmt;
use std::time::Duration;

/// What simulated devices sent and how the server answered.
///
/// Expected outcomes, such as the negative acknowledgment of a packet sent
/// with a broken CRC on purpose, are counted apart from unexpected ones;
/// [`unexpected`](Self::unexpected) sums the latter, so a clean run against
/// a correct server reports 0.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// Simulated devices.
    pub devices: u64,
    /// Connections opened (TCP), reconnections included.
    pub connections: u64,
    /// Packets sent, resends included.
    pub packets: u64,
    /// Packets sent again because the server didn't acknowledge all of
    /// their records, as a device does.
    pub resent: u64,
    /// Records sent, resends included.
    pub records: u64,
    /// Records the server acknowledged.
    pub records_acked: u64,
    /// Packets the server rejected with a negative acknowledgment, as
    /// expected for a fault.
    pub expected_nacks: u64,
    /// Packets sent with a fault that expects no acknowledgment.
    pub expected_drops: u64,
    /// Faults injected.
    pub faults: u64,
    /// Codec 12 commands received.
    pub commands: u64,
    /// Codec 12 commands answered; unknown commands get no answer.
    pub commands_answered: u64,
    /// Acknowledgments that don't match the packet: a wrong count, a
    /// negative acknowledgment of a valid packet, or wrong UDP IDs.
    pub ack_mismatches: u64,
    /// Packets whose acknowledgment didn't arrive in time.
    pub timeouts: u64,
    /// IMEI handshakes the server refused.
    pub rejected_imeis: u64,
    /// I/O failures, unexpected closes, and bytes that are neither an
    /// acknowledgment nor a Codec 12 frame.
    pub errors: u64,
    /// Time from the end of each send to its positive acknowledgment.
    ///
    /// Negative acknowledgments are left out over TCP: telling one apart
    /// from the start of a Codec 12 frame takes a short wait.
    pub ack_latencies: Vec<Duration>,
    /// Wall time of the whole run.
    pub elapsed: Duration,
}

impl Report {
    /// Adds the counts of `other` to this report.
    pub fn merge(&mut self, other: Report) {
        self.devices += other.devices;
        self.connections += other.connections;
        self.packets += other.packets;
        self.resent += other.resent;
        self.records += other.records;
        self.records_acked += other.records_acked;
        self.expected_nacks += other.expected_nacks;
        self.expected_drops += other.expected_drops;
        self.faults += other.faults;
        self.commands += other.commands;
        self.commands_answered += other.commands_answered;
        self.ack_mismatches += other.ack_mismatches;
        self.timeouts += other.timeouts;
        self.rejected_imeis += other.rejected_imeis;
        self.errors += other.errors;
        self.ack_latencies.extend(other.ack_latencies);
    }

    /// Returns the number of outcomes a correct server doesn't cause:
    /// acknowledgment mismatches, timeouts, refused IMEIs, and errors.
    pub fn unexpected(&self) -> u64 {
        self.ack_mismatches + self.timeouts + self.rejected_imeis + self.errors
    }

    /// Returns the acknowledgment latency at `quantile` (0 to 1), or `None`
    /// if nothing was acknowledged.
    pub fn latency(&self, quantile: f64) -> Option<Duration> {
        let mut latencies = self.ack_latencies.clone();
        latencies.sort_unstable();
        let last = latencies.len().checked_sub(1)?;
        let index = ((last as f64) * quantile.clamp(0.0, 1.0)).round() as usize;
        Some(latencies[index])
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.elapsed.as_secs_f64();
        let rate = if seconds > 0.0 {
            self.packets as f64 / seconds
        } else {
            0.0
        };
        writeln!(
            f,
            "devices {}, connections {}, elapsed {seconds:.2} s",
            self.devices, self.connections
        )?;
        writeln!(
            f,
            "packets {} ({rate:.1}/s, {} resent), records {}, acknowledged {}",
            self.packets, self.resent, self.records, self.records_acked
        )?;
        writeln!(
            f,
            "faults {}: expected NACKs {}, expected drops {}",
            self.faults, self.expected_nacks, self.expected_drops
        )?;
        writeln!(
            f,
            "commands {}, answered {}",
            self.commands, self.commands_answered
        )?;
        writeln!(
            f,
            "unexpected {}: ack mismatches {}, timeouts {}, refused IMEIs {}, errors {}",
            self.unexpected(),
            self.ack_mismatches,
            self.timeouts,
            self.rejected_imeis,
            self.errors
        )?;
        match (self.latency(0.5), self.latency(0.99), self.latency(1.0)) {
            (Some(p50), Some(p99), Some(max)) => write!(
                f,
                "ack latency p50 {:.3} ms, p99 {:.3} ms, max {:.3} ms",
                p50.as_secs_f64() * 1e3,
                p99.as_secs_f64() * 1e3,
                max.as_secs_f64() * 1e3
            ),
            _ => f.write_str("ack latency: no acknowledgment"),
        }
    }
}
