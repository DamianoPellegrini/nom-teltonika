//! Simulated Teltonika devices, for testing, load testing, and benchmarking
//! servers built on `nom-teltonika`.
//!
//! A simulated device behaves as an FMB device does: it connects over TCP or
//! UDP with a valid IMEI, sends AVL records taken in real time from a
//! vehicle that drives and parks, with the IO elements an FMB003 sends, and
//! waits for each acknowledgment. What isn't acknowledged, it sends again.
//! Over TCP it answers Codec 12 commands in the device's own words. Traffic
//! is deterministic for a given seed, apart from the clock, so a failing run
//! can be replayed.
//!
//! Faults can be injected on purpose ([`Fault`]) to check how a server
//! handles broken devices; each fault has an expected server reaction, and
//! the [`Report`] separates expected outcomes from unexpected ones.
//!
//! The binary (`teltonika-simulator`) wraps [`run`] and [`Traffic`] in a
//! command line; tests call them directly.

mod commands;
mod fault;
mod report;
mod run;
mod tcp;
mod traffic;
mod udp;

pub use fault::{Fault, Faults};
pub use report::Report;
pub use run::{RunConfig, Stop, Transport, imei, run};
pub use traffic::{Packet, Traffic};
