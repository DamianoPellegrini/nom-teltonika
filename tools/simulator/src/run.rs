use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nom_teltonika::protocol::AvlCodec;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep};

use crate::{Faults, Report, Traffic, tcp, udp};

/// The transport simulated devices use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum Transport {
    /// A TCP connection per device: IMEI handshake, AVL frames, Codec 12.
    Tcp,
    /// A UDP socket per device: AVL datagrams.
    Udp,
}

/// When each simulated device stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// After sending this many packets.
    Packets(u64),
    /// Once this much time has passed since the run started.
    After(Duration),
}

/// The settings of a simulation run.
#[derive(Debug, Clone, PartialEq)]
pub struct RunConfig {
    /// Server address.
    pub server: SocketAddr,
    /// Transport of every device.
    pub transport: Transport,
    /// Number of simulated devices.
    pub devices: u32,
    /// Codec of the AVL packets.
    pub codec: AvlCodec,
    /// Records in each packet.
    pub records_per_packet: u8,
    /// Time between two packets of a device.
    pub interval: Duration,
    /// When each device stops.
    pub stop: Stop,
    /// Seed of the traffic and the faults; device `i` uses `seed + i`.
    pub seed: u64,
    /// Type Allocation Code: the first 8 IMEI digits, which name the model.
    /// Device `i` gets serial number `i` and a Luhn check digit, as real
    /// IMEIs have.
    pub tac: u32,
    /// Faults to inject.
    pub faults: Faults,
    /// How long a device waits for an acknowledgment.
    pub ack_timeout: Duration,
    /// Time over which device starts are spread, so they don't all connect
    /// at once.
    pub ramp_up: Duration,
}

/// Runs the simulation and returns the merged report of every device.
///
/// Devices run concurrently on the current Tokio runtime. A device that
/// can't connect, or whose connection fails, counts an error; with TCP it
/// reconnects and goes on while there is something left to send.
pub async fn run(config: RunConfig) -> Report {
    let config = Arc::new(config);
    let started = Instant::now();
    let deadline = match config.stop {
        Stop::After(duration) => Some(started + duration),
        Stop::Packets(_) => None,
    };

    let mut devices = JoinSet::new();
    for index in 0..config.devices {
        let config = Arc::clone(&config);
        let delay = config
            .ramp_up
            .mul_f64(f64::from(index) / f64::from(config.devices));
        devices.spawn(async move {
            sleep(delay).await;
            let device = Device::new(&config, index, deadline);
            match config.transport {
                Transport::Tcp => tcp::run_device(&config, device).await,
                Transport::Udp => udp::run_device(&config, device).await,
            }
        });
    }

    let mut report = Report::default();
    while let Some(result) = devices.join_next().await {
        match result {
            Ok(device) => report.merge(device),
            Err(_) => report.errors += 1,
        }
    }
    report.elapsed = started.elapsed();
    report
}

/// Returns the IMEI with the given TAC and serial number: 14 digits and a
/// Luhn check digit.
pub fn imei(tac: u32, serial: u32) -> String {
    let body = format!("{:08}{:06}", tac % 100_000_000, serial % 1_000_000);
    // Luhn: double every second digit from the right of the full number,
    // which is every odd position of the 14-digit body.
    let sum: u32 = body
        .bytes()
        .map(|digit| u32::from(digit - b'0'))
        .enumerate()
        .map(|(index, digit)| match index % 2 {
            1 if digit * 2 > 9 => digit * 2 - 9,
            1 => digit * 2,
            _ => digit,
        })
        .sum();
    format!("{body}{}", (10 - sum % 10) % 10)
}

/// Returns the current time, in milliseconds since the Unix epoch.
pub(crate) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// What every device needs besides the shared configuration.
pub(crate) struct Device {
    /// The IMEI, 15 digits.
    pub(crate) imei: String,
    /// Seed of this device's traffic and faults.
    pub(crate) seed: u64,
    pub(crate) mac: [u8; 6],
    /// When the device started, in milliseconds since the Unix epoch.
    pub(crate) init_millis: u64,
    pub(crate) deadline: Option<Instant>,
    pub(crate) report: Report,
}

impl Device {
    fn new(config: &RunConfig, index: u32, deadline: Option<Instant>) -> Self {
        let seed = config.seed.wrapping_add(u64::from(index));
        let mut rng = fastrand::Rng::with_seed(seed ^ 0x0ac0_ffee);
        // A device has been running for a while when the test starts.
        let init_millis = now_millis().saturating_sub(rng.u64(60_000..=86_400_000));
        Self {
            imei: imei(config.tac, index),
            seed,
            mac: std::array::from_fn(|_| rng.u8(..)),
            init_millis,
            deadline,
            report: Report {
                devices: 1,
                ..Report::default()
            },
        }
    }

    /// Returns this device's traffic, in real time: each packet holds the
    /// records taken over the interval before it is sent.
    pub(crate) fn traffic(&self, config: &RunConfig) -> Traffic {
        let records = u64::from(config.records_per_packet);
        // Without an interval, as in tests, records are a second apart.
        let period = match config.interval.as_millis() as u64 / records {
            0 => 1_000,
            period => period,
        };
        let start = now_millis().saturating_sub(period * records);
        Traffic::new(
            config.codec,
            config.records_per_packet,
            period,
            self.seed,
            start,
        )
    }

    /// Returns `true` once the device has sent everything it should.
    pub(crate) fn done(&self, config: &RunConfig) -> bool {
        match config.stop {
            Stop::Packets(count) => self.report.packets >= count,
            Stop::After(_) => self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline),
        }
    }
}
