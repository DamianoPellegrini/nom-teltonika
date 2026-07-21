#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod encode;
mod parser;
mod protocol;
mod stream;
mod udp;

pub use encode::{
    encode_avl_ack, encode_avl_nack, encode_codec12_command, encode_codec12_commands,
    encode_imei_approval, encode_udp_ack, write_codec12_commands,
};
pub use parser::{
    crc16, parse_imei, parse_tcp_frame, parse_tcp_frame_with_limits, parse_udp_datagram,
    parse_udp_datagram_with_limits,
};
pub use protocol::{
    AvlCodec, AvlPacket, AvlRecord, AvlTimestamp, Codec12Message, Codec12Packet, CountStatus,
    FatalReason, Frame, GenerationType, GpsElement, Imei, ImeiError, IoElement, IoId, IoValue,
    Limits, LimitsError, ParseError, Parsed, Priority, RejectionReason, TimestampError,
    UdpDatagram,
};
pub use stream::{StreamConfig, StreamConfigError, StreamError, TeltonikaStream};
pub use udp::{TeltonikaUdpSocket, UdpSocketError};
