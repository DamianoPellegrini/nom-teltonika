mod common;

use std::io::Cursor;

use common::*;
use nom_teltonika::{parser::*, protocol::*, stream::*};

#[test]
fn should_read_frame_across_every_stream_read_size() {
    let frame = bytes(CODEC8_EXTENDED);
    for chunk in 1..=frame.len() {
        let reader = ChunkedReader {
            inner: Cursor::new(frame.clone()),
            chunk,
        };
        let mut stream = TeltonikaStream::new(reader);
        let Frame::Avl(packet) = stream.read_frame().unwrap() else {
            panic!()
        };
        assert_eq!(packet.codec(), AvlCodec::Codec8Extended);
    }
}

#[test]
fn should_distinguish_closed_from_truncated_stream() {
    let mut closed = TeltonikaStream::new(Cursor::new(Vec::<u8>::new()));
    assert!(matches!(closed.read_frame(), Err(StreamError::Closed)));
    let mut truncated = TeltonikaStream::new(Cursor::new(bytes(&CODEC8[..20])));
    assert!(matches!(
        truncated.read_frame(),
        Err(StreamError::Truncated { .. })
    ));
}

#[test]
fn should_consume_rejection_before_reading_next_valid_frame() {
    let mut rejected = bytes(CODEC8);
    let last = rejected.len() - 1;
    rejected[last] ^= 1;
    rejected.extend_from_slice(&bytes(CODEC12_COMMAND));
    let mut stream = TeltonikaStream::new(Cursor::new(rejected));
    assert!(matches!(
        stream.read_frame(),
        Err(StreamError::Parse(ParseError::Rejected { .. }))
    ));
    assert!(matches!(stream.read_frame().unwrap(), Frame::Codec12(_)));
}

#[test]
fn should_flush_protocol_writes() {
    let mut stream = TeltonikaStream::new(Cursor::new(Vec::new()));
    stream.write_imei_approval(true).unwrap();
    stream.write_avl_ack(2).unwrap();
    stream.write_command(b"getinfo").unwrap();
    let output = stream.into_inner().into_inner();
    assert_eq!(&output[..5], &[1, 0, 0, 0, 2]);
    assert_eq!(&output[5..], bytes(CODEC12_COMMAND));
}

#[test]
fn should_reject_zero_or_incoherent_stream_configuration() {
    assert!(matches!(
        StreamConfig::new(0, Limits::default()),
        Err(StreamConfigError::ZeroReadSize)
    ));
    assert!(Limits::new(14, 16, 23).is_err());
}
