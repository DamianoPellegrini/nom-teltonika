#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[path = "checksum.rs"]
mod checksum;
#[path = "decoder.rs"]
mod decoder_impl;
#[path = "encoder.rs"]
mod encoder_impl;
#[path = "protocol.rs"]
mod protocol_impl;
#[path = "tcp.rs"]
mod tcp;
#[path = "udp.rs"]
mod udp_impl;

/// Protocol response and command encoders.
///
/// Use these functions when your application owns the transport or needs to
/// queue encoded responses before writing them. The encoders do not perform
/// I/O and do not decide whether a packet should be acknowledged.
pub mod encoder {
    pub use crate::checksum::crc16;
    pub use crate::encoder_impl::{
        EncodeError, encode_avl_ack, encode_avl_nack, encode_codec12_command,
        encode_codec12_commands, encode_imei_approval, encode_udp_ack,
    };
}

/// Decoders, decoder limits, and decoding failures.
///
/// The decoders operate on caller-owned byte slices and return owned protocol
/// values. They decode at most one frame or datagram and report its byte count,
/// so they can be used with custom receive buffers.
pub mod decoder {
    pub use crate::decoder_impl::{
        decode_imei, decode_tcp_frame, decode_tcp_frame_with_limits, decode_udp_datagram,
        decode_udp_datagram_with_limits,
    };
    pub use crate::protocol_impl::{
        DecodeError, Decoded, FatalReason, LimitsError, RejectionReason, TcpLimits, UdpDecodeError,
        UdpLimits,
    };
}

/// Owned protocol values produced by the decoders.
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
/// [`TeltonikaTcpStream`] reads only when requested, returns owned frames, and
/// never sends acknowledgments automatically. This lets the application place
/// its own persistence or queue boundary before acknowledging device data.
///
/// [`TeltonikaTcpStream`]: stream::TeltonikaTcpStream
pub mod stream {
    pub use crate::tcp::{
        CommandWriteError, StreamConfig, StreamConfigError, StreamReadError, TeltonikaTcpStream,
    };
}

/// UDP socket handling with explicit peer addressing.
///
/// UDP is kept separate from [`crate::stream::TeltonikaTcpStream`] because a byte
/// stream cannot preserve datagram boundaries, truncation, and source
/// addresses. Acknowledgment methods require a destination to remain safe when
/// one server socket handles multiple devices.
pub mod udp {
    pub use crate::udp_impl::{TeltonikaUdpSocket, UdpReceiveError};
}
