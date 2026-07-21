use std::{error::Error, io, num::NonZeroUsize};

use nom_teltonika::{
    decoder::{DecodeError, FatalReason, LimitsError, RejectionReason, UdpDecodeError},
    encoder::EncodeError,
    protocol::{ImeiError, TimestampError},
    stream::{CommandWriteError, StreamConfigError, StreamReadError},
    udp::UdpReceiveError,
};

#[test]
fn leaf_error_variants_have_no_source() {
    let errors: Vec<Box<dyn Error>> = vec![
        Box::new(DecodeError::Incomplete {
            needed: NonZeroUsize::new(1).unwrap(),
        }),
        Box::new(DecodeError::Rejected {
            consumed: 1,
            offset: 0,
            reason: RejectionReason::InvalidPayloadLength,
        }),
        Box::new(DecodeError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidPreamble,
        }),
        Box::new(DecodeError::Fatal {
            offset: 0,
            reason: FatalReason::InvalidImeiLength {
                declared: 14,
                expected: 15,
            },
        }),
        Box::new(UdpDecodeError::TruncatedHeader { actual: 1 }),
        Box::new(UdpDecodeError::LengthMismatch {
            declared: 2,
            actual: 3,
        }),
        Box::new(UdpDecodeError::DatagramTooLarge {
            declared: 3,
            limit: 2,
        }),
        Box::new(UdpDecodeError::Invalid {
            offset: 0,
            reason: RejectionReason::InvalidPayloadLength,
        }),
        Box::new(ImeiError::InvalidLength { actual: 14 }),
        Box::new(ImeiError::InvalidDigit { index: 2 }),
        Box::new(TimestampError::BeforeUnixEpoch),
        Box::new(TimestampError::OutOfRange),
        Box::new(EncodeError::EmptyCommandBatch),
        Box::new(EncodeError::TooManyCommands {
            actual: 256,
            maximum: 255,
        }),
        Box::new(EncodeError::CommandTooLarge {
            index: 0,
            actual: usize::MAX,
            maximum: u32::MAX as usize,
        }),
        Box::new(EncodeError::FrameTooLarge),
        Box::new(LimitsError::AvlFrameTooSmall {
            actual: 44,
            minimum: 45,
        }),
        Box::new(LimitsError::Codec12FrameTooSmall {
            actual: 19,
            minimum: 20,
        }),
        Box::new(LimitsError::UdpDatagramTooSmall {
            actual: 55,
            minimum: 56,
        }),
        Box::new(LimitsError::UdpDatagramTooLarge {
            actual: 65_538,
            maximum: 65_537,
        }),
        Box::new(StreamConfigError::ZeroReadSize),
        Box::new(StreamReadError::Closed),
        Box::new(StreamReadError::Truncated {
            buffered: 1,
            needed: NonZeroUsize::new(1).unwrap(),
        }),
        Box::new(UdpReceiveError::Truncated {
            received_at_least: 57,
            limit: 56,
        }),
    ];

    for error in errors {
        assert!(!error.to_string().is_empty());
        assert!(error.source().is_none(), "unexpected source for {error}");
    }
}

#[test]
fn wrapper_error_variants_expose_their_sources() {
    let decode = StreamReadError::Decode(DecodeError::Fatal {
        offset: 0,
        reason: FatalReason::InvalidPreamble,
    });
    let stream_io = StreamReadError::Io(io::Error::other("read"));
    let command_encode = CommandWriteError::Encode(EncodeError::EmptyCommandBatch);
    let command_io = CommandWriteError::Io(io::Error::other("write"));
    let udp_decode = UdpReceiveError::Decode(UdpDecodeError::TruncatedHeader { actual: 0 });
    let udp_io = UdpReceiveError::Io(io::Error::other("receive"));

    for error in [
        &decode as &dyn Error,
        &stream_io,
        &command_encode,
        &command_io,
        &udp_decode,
        &udp_io,
    ] {
        assert!(error.source().is_some(), "missing source for {error}");
    }
}
