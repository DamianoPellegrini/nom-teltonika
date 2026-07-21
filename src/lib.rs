#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[path = "encode.rs"]
mod encode_impl;
#[path = "parser.rs"]
mod parser_impl;
#[path = "protocol.rs"]
mod protocol_impl;
#[path = "stream.rs"]
mod stream_impl;
#[path = "udp.rs"]
mod udp_impl;

/// Protocol response and command encoders.
///
/// Use these functions when your application owns the transport or needs to
/// queue encoded responses before writing them. The encoders do not perform
/// I/O and do not decide whether a packet should be acknowledged.
pub mod encode {
    pub use crate::encode_impl::{
        encode_avl_ack, encode_avl_nack, encode_codec12_command, encode_codec12_commands,
        encode_imei_approval, encode_udp_ack, write_codec12_commands,
    };
}

/// Parsers, parser limits, and parse failures.
///
/// The parsers operate on caller-owned byte slices and return owned protocol
/// values. They parse at most one frame or datagram and report its byte count,
/// so they can be used with custom receive buffers.
pub mod parser {
    pub use crate::parser_impl::{
        crc16, parse_imei, parse_tcp_frame, parse_tcp_frame_with_limits, parse_udp_datagram,
        parse_udp_datagram_with_limits,
    };
    pub use crate::protocol_impl::{
        FatalReason, Limits, LimitsError, ParseError, Parsed, RejectionReason,
    };
}

/// Owned protocol values produced by the parsers.
///
/// Successful models contain semantic protocol data, not already-validated
/// framing fields such as lengths, preambles, CRC values, or duplicate AVL
/// counts. Variable-length payloads remain bytes unless you explicitly decode
/// them.
pub mod protocol {
    pub use crate::protocol_impl::{
        AvlCodec, AvlPacket, AvlRecord, AvlTimestamp, Codec12Message, Codec12Packet, CountStatus,
        Frame, GenerationType, GpsElement, Imei, ImeiError, IoElement, IoId, IoValue, Priority,
        TimestampError, UdpDatagram,
    };
}

/// Pull-based synchronous and asynchronous TCP stream handling.
///
/// [`TeltonikaStream`] reads only when requested, returns owned frames, and
/// never sends acknowledgments automatically. This lets the application place
/// its own persistence or queue boundary before acknowledging device data.
///
/// [`TeltonikaStream`]: stream::TeltonikaStream
pub mod stream {
    pub use crate::stream_impl::{StreamConfig, StreamConfigError, StreamError, TeltonikaStream};
}

/// UDP socket handling with explicit peer addressing.
///
/// UDP is kept separate from [`crate::stream::TeltonikaStream`] because a byte
/// stream cannot preserve datagram boundaries, truncation, and source
/// addresses. Acknowledgment methods require a destination to remain safe when
/// one server socket handles multiple devices.
pub mod udp {
    pub use crate::udp_impl::{TeltonikaUdpSocket, UdpSocketError};
}
