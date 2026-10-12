//! Command line for simulated Teltonika devices.
//!
//! `run` drives simulated devices against a server and reports how it
//! answered; `generate` writes deterministic packets for fixtures and
//! benchmarks. See `--help` on each subcommand.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use nom_teltonika::protocol::{AvlCodec, ImeiView};
use teltonika_simulator::{Fault, Faults, RunConfig, Stop, Traffic, Transport, run};

/// Simulated Teltonika devices for testing, load testing, and benchmarking.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Runs simulated devices against a server and prints a report.
    ///
    /// Exits with status 1 if the server answered anything a correct server
    /// doesn't: see the "unexpected" line of the report.
    Run(RunArgs),
    /// Writes deterministic AVL packets, for fixtures and benchmarks.
    Generate(GenerateArgs),
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:5000")]
    server: SocketAddr,
    /// Transport of every device.
    #[arg(long, value_enum, default_value_t = Transport::Tcp)]
    transport: Transport,
    /// Number of simulated devices.
    #[arg(long, default_value_t = 1)]
    devices: u32,
    #[command(flatten)]
    packets: PacketArgs,
    /// Milliseconds between two packets of a device.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    /// Packets each device sends. Defaults to 10 without --duration-s.
    #[arg(long, conflicts_with = "duration_s")]
    packets_per_device: Option<u64>,
    /// Seconds to run, instead of a packet count.
    #[arg(long)]
    duration_s: Option<u64>,
    /// Type Allocation Code, the first 8 IMEI digits. Device `i` gets
    /// serial number `i` and a check digit. The default is the TAC of the
    /// IMEI in the Teltonika wiki's examples.
    #[arg(long, default_value_t = 35_630_704)]
    tac: u32,
    /// Faults to inject, comma-separated.
    #[arg(long, value_enum, value_delimiter = ',')]
    faults: Vec<Fault>,
    /// Probability that a packet gets one of --faults.
    #[arg(long, default_value_t = 0.0)]
    fault_rate: f64,
    /// Milliseconds to wait for an acknowledgment.
    #[arg(long, default_value_t = 5000)]
    ack_timeout_ms: u64,
    /// Milliseconds over which device starts are spread.
    #[arg(long, default_value_t = 0)]
    ramp_up_ms: u64,
}

#[derive(Debug, clap::Args)]
struct PacketArgs {
    /// Codec of the AVL packets.
    #[arg(long, value_enum, default_value_t = CodecArg::Codec8Extended)]
    codec: CodecArg,
    /// Records in each packet.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..))]
    records: u8,
    /// Seed of the traffic; the same seed gives the same bytes.
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

#[derive(Debug, clap::Args)]
struct GenerateArgs {
    #[command(flatten)]
    packets: PacketArgs,
    /// Number of packets.
    #[arg(long, default_value_t = 1)]
    count: u64,
    /// Write UDP datagrams instead of TCP frames.
    #[arg(long)]
    udp: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Hex)]
    format: Format,
    /// Output file; standard output if absent.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CodecArg {
    /// Codec 8.
    #[value(name = "8")]
    Codec8,
    /// Codec 8 Extended.
    #[value(name = "8e")]
    Codec8Extended,
    /// Codec 16.
    #[value(name = "16")]
    Codec16,
}

impl From<CodecArg> for AvlCodec {
    fn from(codec: CodecArg) -> Self {
        match codec {
            CodecArg::Codec8 => AvlCodec::Codec8,
            CodecArg::Codec8Extended => AvlCodec::Codec8Extended,
            CodecArg::Codec16 => AvlCodec::Codec16,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    /// One packet per line, in hexadecimal.
    Hex,
    /// Packets back to back. Datagram boundaries are lost with --udp.
    Bin,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run_command(args),
        Command::Generate(args) => generate(args),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_command(args: RunArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !(0.0..=1.0).contains(&args.fault_rate) {
        return Err("--fault-rate is a probability, between 0 and 1".into());
    }
    let stop = match (args.packets_per_device, args.duration_s) {
        (_, Some(seconds)) => Stop::After(Duration::from_secs(seconds)),
        (packets, None) => Stop::Packets(packets.unwrap_or(10)),
    };
    let config = RunConfig {
        server: args.server,
        transport: args.transport,
        devices: args.devices,
        codec: args.packets.codec.into(),
        records_per_packet: args.packets.records,
        interval: Duration::from_millis(args.interval_ms),
        stop,
        seed: args.packets.seed,
        tac: args.tac,
        faults: Faults::new(args.faults, args.fault_rate),
        ack_timeout: Duration::from_millis(args.ack_timeout_ms),
        ramp_up: Duration::from_millis(args.ramp_up_ms),
    };
    let report = tokio::runtime::Runtime::new()?.block_on(run(config));
    println!("{report}");
    Ok(if report.unexpected() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn generate(args: GenerateArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let codec = args.packets.codec.into();
    // A fixed start and a record per second, so the same seed gives the
    // same bytes.
    let mut traffic = Traffic::new(
        codec,
        args.packets.records,
        1_000,
        args.packets.seed,
        1_700_000_000_000,
    );
    let imei = teltonika_simulator::imei(35_630_704, 0);
    let imei = ImeiView::try_from(imei.as_str())?;
    let mut out: Box<dyn Write> = match &args.out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    for index in 0..args.count {
        let packet = if args.udp {
            traffic.next_datagram(index as u16, index as u8, imei)?
        } else {
            traffic.next_frame()?
        }
        .bytes;
        match args.format {
            Format::Bin => out.write_all(&packet)?,
            Format::Hex => {
                for byte in &packet {
                    write!(out, "{byte:02X}")?;
                }
                writeln!(out)?;
            }
        }
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}
