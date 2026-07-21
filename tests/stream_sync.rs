mod common;

use std::io::{self, Cursor, Read, Write};

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
        let mut stream = TeltonikaTcpStream::new(reader);
        let Frame::Avl(packet) = stream.read_frame().unwrap() else {
            panic!()
        };
        assert_eq!(packet.codec(), AvlCodec::Codec8Extended);
    }
}

#[test]
fn should_distinguish_closed_from_truncated_stream() {
    let mut closed = TeltonikaTcpStream::new(Cursor::new(Vec::<u8>::new()));
    assert!(matches!(closed.read_frame(), Err(StreamReadError::Closed)));
    let partial = bytes(&CODEC8[..20]);
    let buffered = partial.len();
    let mut truncated = TeltonikaTcpStream::new(Cursor::new(partial));
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
    let mut stream = TeltonikaTcpStream::new(Cursor::new(rejected));
    assert!(matches!(
        stream.read_frame(),
        Err(StreamReadError::Decode(DecodeError::Rejected { .. }))
    ));
    assert!(matches!(stream.read_frame().unwrap(), Frame::Codec12(_)));
}

#[test]
fn should_read_ahead_using_the_configured_chunk_size() {
    let mut input = bytes(CODEC8);
    input.extend_from_slice(&bytes(CODEC12_COMMAND));
    let read_size = input.len() + 16;
    let reader = ObservedReader::new(input);
    let config = StreamConfig::new(read_size, TcpLimits::default()).unwrap();
    let mut stream = TeltonikaTcpStream::with_config(reader, config).unwrap();

    assert!(matches!(stream.read_frame().unwrap(), Frame::Avl(_)));
    assert_eq!(stream.get_ref().requested, vec![read_size]);
    assert!(matches!(stream.read_frame().unwrap(), Frame::Codec12(_)));
    assert_eq!(stream.get_ref().requested, vec![read_size]);
}

#[test]
fn should_preserve_frames_while_compacting_the_stream_buffer() {
    let frame = bytes(CODEC12_COMMAND);
    let frame_count = 64;
    let input = frame.repeat(frame_count);
    let config = StreamConfig::new(frame.len() + 7, TcpLimits::default()).unwrap();
    let mut stream = TeltonikaTcpStream::with_config(Cursor::new(input), config).unwrap();

    for _ in 0..frame_count {
        assert!(matches!(stream.read_frame().unwrap(), Frame::Codec12(_)));
    }
    assert!(matches!(stream.read_frame(), Err(StreamReadError::Closed)));
}

#[test]
fn should_write_and_flush_each_protocol_message() {
    let mut stream = TeltonikaTcpStream::new(ObservedWriter::default());

    stream.write_imei_approval(true).unwrap();
    assert_eq!(stream.get_ref().flush_count, 1);

    stream.write_avl_ack(2).unwrap();
    assert_eq!(stream.get_ref().flush_count, 2);

    stream.write_command(b"getinfo").unwrap();
    assert_eq!(stream.get_ref().flush_count, 3);

    let output = stream.into_inner().output;
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

struct ObservedReader {
    inner: Cursor<Vec<u8>>,
    requested: Vec<usize>,
}

impl ObservedReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            requested: Vec::new(),
        }
    }
}

impl Read for ObservedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.requested.push(output.len());
        self.inner.read(output)
    }
}

#[derive(Default)]
struct ObservedWriter {
    output: Vec<u8>,
    flush_count: usize,
}

impl Write for ObservedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}
