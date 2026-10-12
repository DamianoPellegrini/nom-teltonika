#![cfg(feature = "alloc")]

use std::{error::Error, num::NonZeroUsize};

use nom_teltonika::{
    decoder::{
        AvlPacketError, DatagramError, DecodeDatagramError, DecodeFrameError, DecodeImeiError,
        FrameError, GprsPacketError, HeaderError, take_datagram,
    },
    encoder::{EncodeAvlError, EncodeGprsError},
    protocol::{DatagramIds, ImeiError, IoId, TimestampError},
};

fn assert_std_style(error: &dyn Error) {
    let message = error.to_string();
    assert!(!message.is_empty());
    assert!(!message.ends_with('.'), "trailing period in {message:?}");
}

/// The IDs of the wiki's UDP example, which only a datagram hands out.
fn datagram_ids() -> DatagramIds {
    let bytes = hex::decode("003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001").unwrap();
    take_datagram(&mut &bytes[..]).unwrap().ids()
}

#[test]
fn leaf_error_variants_have_no_source() {
    let needed = NonZeroUsize::new(1).unwrap();
    let errors: Vec<Box<dyn Error>> = vec![
        Box::new(DecodeImeiError::Incomplete { needed }),
        Box::new(DecodeFrameError::Incomplete { needed }),
        Box::new(FrameError::NoData),
        Box::new(FrameError::CrcMismatch {
            expected: 1,
            received: 2,
        }),
        Box::new(FrameError::UnsupportedCodec(0x0d)),
        Box::new(HeaderError::InvalidPreamble {
            found: [1, 0, 0, 0],
        }),
        Box::new(HeaderError::TooLong {
            declared: 1281,
            limit: 1280,
        }),
        Box::new(AvlPacketError::Truncated),
        Box::new(AvlPacketError::NoRecords),
        Box::new(AvlPacketError::RecordCountMismatch {
            first: 1,
            second: 2,
        }),
        Box::new(AvlPacketError::TrailingBytes),
        Box::new(AvlPacketError::InvalidPriority(3)),
        Box::new(AvlPacketError::InvalidGenerationType(8)),
        Box::new(AvlPacketError::IoCountMismatch {
            declared: 6,
            counted: 5,
        }),
        Box::new(GprsPacketError::Truncated),
        Box::new(GprsPacketError::NoMessages),
        Box::new(GprsPacketError::InvalidMessageType(0x11)),
        Box::new(GprsPacketError::TrailingBytes),
        Box::new(DecodeDatagramError::NoHeader),
        Box::new(DatagramError::Truncated),
        Box::new(DatagramError::LengthMismatch {
            declared: 2,
            actual: 3,
        }),
        Box::new(DatagramError::UnsupportedCodec(0x0c)),
        Box::new(ImeiError { index: 2 }),
        Box::new(TimestampError::BeforeUnixEpoch),
        Box::new(TimestampError::OutOfRange),
        Box::new(EncodeGprsError::NoMessages),
        Box::new(EncodeGprsError::TooManyMessages {
            count: 256,
            limit: 255,
        }),
        Box::new(EncodeGprsError::FrameTooLong {
            len: 39_036,
            limit: 39_035,
        }),
        Box::new(EncodeGprsError::BufferTooSmall { needed: 27 }),
        Box::new(EncodeAvlError::NoRecords),
        Box::new(EncodeAvlError::TooManyRecords {
            count: 256,
            limit: 255,
        }),
        Box::new(EncodeAvlError::IoIdTooWide {
            id: IoId::from(256),
            limit: 255,
        }),
        Box::new(EncodeAvlError::ZeroEventIoId),
        Box::new(EncodeAvlError::MissingGenerationType),
        Box::new(EncodeAvlError::UnexpectedGenerationType),
        Box::new(EncodeAvlError::VariableIoNotSupported),
        Box::new(EncodeAvlError::TooManyIoElements {
            count: 256,
            limit: 255,
        }),
        Box::new(EncodeAvlError::IoValueTooLong {
            id: IoId::from(1),
            len: 65_536,
        }),
        Box::new(EncodeAvlError::TooLong {
            len: 1281,
            limit: 1280,
        }),
        Box::new(EncodeAvlError::BufferTooSmall { needed: 45 }),
    ];

    for error in errors {
        assert_std_style(&*error);
        assert!(error.source().is_none(), "unexpected source for {error}");
    }
}

#[test]
fn wrapper_error_variants_expose_their_sources() {
    let imei = ImeiError { index: 0 };
    let avl = AvlPacketError::NoRecords;
    let errors: Vec<Box<dyn Error>> = vec![
        Box::new(DecodeImeiError::NotAscii(imei)),
        Box::new(DecodeFrameError::InvalidFrame {
            len: 12,
            reason: FrameError::NoData,
        }),
        Box::new(DecodeFrameError::InvalidHeader(
            HeaderError::InvalidPreamble {
                found: [1, 0, 0, 0],
            },
        )),
        Box::new(FrameError::Avl(avl)),
        Box::new(FrameError::Gprs(GprsPacketError::NoMessages)),
        Box::new(DecodeDatagramError::InvalidDatagram {
            ids: datagram_ids(),
            reason: DatagramError::Truncated,
        }),
        Box::new(DatagramError::ImeiNotAscii(imei)),
        Box::new(DatagramError::Avl(avl)),
    ];

    for error in errors {
        assert_std_style(&*error);
        let source = error.source().expect("wrapper errors have a source");
        assert_ne!(error.to_string(), source.to_string());
    }
}

#[cfg(feature = "std")]
#[test]
fn io_errors_follow_the_same_rules() {
    use std::io;

    use nom_teltonika::{
        tcp::{ReadFrameError, ReadImeiError, WriteCommandError},
        udp::ReceiveDatagramError,
    };

    let needed = NonZeroUsize::new(1).unwrap();
    let leaves: Vec<Box<dyn Error>> = vec![
        Box::new(ReadImeiError::Closed),
        Box::new(ReadImeiError::Truncated {
            buffered: 1,
            needed,
        }),
        Box::new(ReadFrameError::Closed),
        Box::new(ReadFrameError::Truncated {
            buffered: 1,
            needed,
        }),
        Box::new(ReceiveDatagramError::NoHeader {
            peer: ([127, 0, 0, 1], 5000).into(),
        }),
    ];
    for error in leaves {
        assert_std_style(&*error);
        assert!(error.source().is_none(), "unexpected source for {error}");
    }

    let wrappers: Vec<Box<dyn Error>> = vec![
        Box::new(ReadImeiError::NotAscii(ImeiError { index: 0 })),
        Box::new(ReadImeiError::Io(io::Error::other("read"))),
        Box::new(ReadFrameError::InvalidFrame(FrameError::NoData)),
        Box::new(ReadFrameError::InvalidHeader(
            HeaderError::InvalidPreamble {
                found: [1, 0, 0, 0],
            },
        )),
        Box::new(ReadFrameError::Io(io::Error::other("read"))),
        Box::new(WriteCommandError::Encode(EncodeGprsError::NoMessages)),
        Box::new(WriteCommandError::Io(io::Error::other("write"))),
        Box::new(ReceiveDatagramError::InvalidDatagram {
            peer: ([127, 0, 0, 1], 5000).into(),
            ids: datagram_ids(),
            reason: DatagramError::Truncated,
        }),
        Box::new(ReceiveDatagramError::Io(io::Error::other("receive"))),
    ];
    for error in wrappers {
        assert_std_style(&*error);
        assert!(error.source().is_some(), "missing source for {error}");
    }
}
