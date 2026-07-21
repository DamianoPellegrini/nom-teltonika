mod common;

use std::io::Cursor;

use common::*;
use nom_teltonika::{decoder::*, protocol::*, stream::*};

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
    assert!(matches!(closed.read_frame(), Err(StreamReadError::Closed)));
    let partial = bytes(&CODEC8[..20]);
    let buffered = partial.len();
    let mut truncated = TeltonikaStream::new(Cursor::new(partial));
    assert!(matches!(
        truncated.read_frame(),
        Err(StreamReadError::Truncated { buffered: actual, needed })
            if actual == buffered && needed.get() == bytes(CODEC8).len() - buffered
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
        Err(StreamReadError::Decode(DecodeError::Rejected { .. }))
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
        StreamConfig::new(0, TcpLimits::default()),
        Err(StreamConfigError::ZeroReadSize)
    ));
    assert!(TcpLimits::new(44, 20).is_err());
}

#[test]
fn should_expose_validated_stream_configuration() {
    let limits = TcpLimits::new(1280, 65_536).unwrap();
    let config = StreamConfig::new(8192, limits).unwrap();

    assert_eq!(config.read_size(), 8192);
    assert_eq!(config.limits(), limits);
}
