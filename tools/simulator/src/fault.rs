use nom_teltonika::crc16;

/// A fault a simulated device can inject into a packet.
///
/// Each fault has the server reaction that a correct server shows, which the
/// device checks: see the variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum Fault {
    /// Flips a CRC byte (TCP). Expected: a negative acknowledgment.
    BadCrc,
    /// Makes the two record counts differ, with a valid CRC. Expected: a
    /// negative acknowledgment over TCP, no acknowledgment over UDP.
    WrongCount,
    /// Sends half the packet, then closes the connection (TCP) or stops
    /// (UDP). Expected: no acknowledgment; the device reconnects.
    Truncate,
    /// Writes the frame one byte at a time (TCP). Expected: a normal
    /// acknowledgment.
    Slow,
    /// Closes the connection and reconnects before sending (TCP). Expected:
    /// a new IMEI handshake, then a normal acknowledgment.
    Disconnect,
}

/// Which faults a device injects, and how often.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Faults {
    kinds: Vec<Fault>,
    rate: f64,
}

impl Faults {
    /// Creates a fault plan: each packet gets one of `kinds`, picked at
    /// random, with probability `rate`.
    ///
    /// # Panics
    ///
    /// Panics if `rate` is not between 0 and 1.
    pub fn new(kinds: Vec<Fault>, rate: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&rate),
            "the fault rate is a probability"
        );
        Self { kinds, rate }
    }

    /// Creates a plan that injects no fault.
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns the fault for the next packet, if any.
    pub(crate) fn pick(&self, rng: &mut fastrand::Rng) -> Option<Fault> {
        if self.kinds.is_empty() || rng.f64() >= self.rate {
            return None;
        }
        Some(self.kinds[rng.usize(..self.kinds.len())])
    }
}

/// Flips the last CRC byte of a TCP frame.
pub(crate) fn break_crc(frame: &mut [u8]) {
    let last = frame.len() - 1;
    frame[last] ^= 0xff;
}

/// Changes the second record count of a TCP frame and fixes its CRC, so
/// only the counts disagree.
pub(crate) fn break_tcp_count(frame: &mut [u8]) {
    let len = frame.len();
    frame[len - 5] = frame[len - 5].wrapping_add(1);
    let crc = crc16(&frame[8..len - 4]);
    frame[len - 4..].copy_from_slice(&u32::from(crc).to_be_bytes());
}

/// Changes the second record count of a UDP datagram, which has no CRC.
pub(crate) fn break_udp_count(datagram: &mut [u8]) {
    let last = datagram.len() - 1;
    datagram[last] = datagram[last].wrapping_add(1);
}
