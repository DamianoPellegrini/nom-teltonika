#![cfg(feature = "std")]

mod common;

use std::io::{self, Cursor, Read, Write};

use common::*;
use nom_teltonika::{decoder::*, protocol::*, tcp::*};

#[test]
fn should_read_frame_across_every_transport_chunk_size() {
    let frame = bytes(CODEC8_EXTENDED);
    for chunk in 1..=frame.len() {
        let reader = ChunkedReader {
            inner: Cursor::new(frame.clone()),
            chunk,
        };
        let mut stream = TeltonikaTcpStream::new(reader);
        let FrameView::Avl(packet) = stream.read_frame().unwrap() else {
            panic!("expected AVL")
        };
        assert_eq!(packet.codec(), AvlCodec::Codec8Extended);
    }
}

#[test]
fn should_read_the_imei_handshake_then_frames() {
    let mut input = bytes("000F333536333037303432343431303133");
    input.extend_from_slice(&bytes(CODEC8));
    let reader = ChunkedReader {
        inner: Cursor::new(input),
        chunk: 3,
    };
    let mut stream = TeltonikaTcpStream::new(reader);

    let imei = stream.read_imei().unwrap().evaluate();
    assert_eq!(imei.as_str(), "356307042441013");
    assert!(matches!(stream.read_frame().unwrap(), FrameView::Avl(_)));
    assert!(matches!(stream.read_frame(), Err(ReadFrameError::Closed)));
}

#[test]
fn should_reject_an_invalid_imei_handshake() {
    // Any declared length is honored: the buffer grows for a long one.
    let mut long = vec![b'1'; 2 + 2000];
    long[..2].copy_from_slice(&2000u16.to_be_bytes());
    let mut stream = TeltonikaTcpStream::new(Cursor::new(long));
    assert_eq!(stream.read_imei().unwrap().len(), 2000);

    let mut stream = TeltonikaTcpStream::new(Cursor::new(vec![0x00, 0x01, 0xe9]));
    assert!(matches!(
        stream.read_imei(),
        Err(ReadImeiError::NotAscii(ImeiError { index: 0 }))
    ));
    assert!(matches!(stream.read_imei(), Err(ReadImeiError::Closed)));

    let mut stream = TeltonikaTcpStream::new(Cursor::new(vec![0x00, 0x0f, b'3']));
    assert!(matches!(
        stream.read_imei(),
        Err(ReadImeiError::Truncated { buffered: 3, needed }) if needed.get() == 14
    ));
}

#[test]
fn should_distinguish_closed_from_truncated_stream() {
    let mut closed = TeltonikaTcpStream::new(Cursor::new(Vec::<u8>::new()));
    assert!(matches!(closed.read_frame(), Err(ReadFrameError::Closed)));
    let partial = bytes(&CODEC8[..40]);
    let buffered = partial.len();
    let mut truncated = TeltonikaTcpStream::new(Cursor::new(partial));
    assert!(matches!(
        truncated.read_frame(),
        Err(ReadFrameError::Truncated { buffered: actual, needed })
            if actual == buffered && needed.get() == bytes(CODEC8).len() - buffered
    ));
}

#[test]
fn should_consume_an_invalid_frame_before_reading_the_next_one() {
    let mut invalid = bytes(CODEC8);
    let last = invalid.len() - 1;
    invalid[last] ^= 1;
    invalid.extend_from_slice(&bytes(CODEC12_COMMAND));
    let mut stream = TeltonikaTcpStream::new(Cursor::new(invalid));
    assert!(matches!(
        stream.read_frame(),
        Err(ReadFrameError::InvalidFrame(FrameError::CrcMismatch { .. }))
    ));
    assert!(matches!(stream.read_frame().unwrap(), FrameView::Gprs(_)));
}

#[test]
fn should_stop_at_an_invalid_header() {
    let mut input = bytes(CODEC8);
    input[0] = 1;
    let mut stream = TeltonikaTcpStream::new(Cursor::new(input));
    for _ in 0..2 {
        assert!(matches!(
            stream.read_frame(),
            Err(ReadFrameError::InvalidHeader(
                HeaderError::InvalidPreamble { .. }
            ))
        ));
    }
}

#[test]
fn should_ask_for_all_the_free_space_in_each_read() {
    let mut input = bytes(CODEC8);
    input.extend_from_slice(&bytes(CODEC12_COMMAND));
    let mut stream = TeltonikaTcpStream::with_capacity(2560, ObservedReader::new(input));
    assert_eq!(stream.capacity(), 2560);

    assert!(matches!(stream.read_frame().unwrap(), FrameView::Avl(_)));
    assert_eq!(stream.get_ref().requested, vec![2560]);
    // The second frame came in the same read, and is there to hand back.
    assert_eq!(stream.buffer(), bytes(CODEC12_COMMAND));
    assert!(matches!(stream.read_frame().unwrap(), FrameView::Gprs(_)));
    assert_eq!(stream.get_ref().requested, vec![2560]);
}

#[test]
fn should_raise_a_capacity_under_the_longest_avl_frame() {
    let stream = TeltonikaTcpStream::with_capacity(0, Cursor::new(b""));
    assert_eq!(stream.capacity(), 1280);
}

#[test]
fn should_grow_once_for_a_frame_longer_than_the_buffer_and_shrink_when_asked() {
    let text = vec![b'a'; 5000];
    let frame = nom_teltonika::encoder::encode_gprs_frame(
        nom_teltonika::protocol::GprsMessageType::Response,
        &[&text],
    )
    .unwrap();
    let mut stream = TeltonikaTcpStream::new(ObservedReader::new(frame.clone()));
    assert_eq!(stream.capacity(), 1280);

    let FrameView::Gprs(packet) = stream.read_frame().unwrap() else {
        panic!("expected Codec 12")
    };
    assert_eq!(packet.messages().next().unwrap().payload(), text);
    // Filled its 1280 bytes, then grew once to the frame's length rounded
    // up to a power of two.
    assert_eq!(stream.capacity(), 8192);
    assert_eq!(stream.get_ref().requested, vec![1280, 8192 - 1280]);

    // It keeps that size until asked to shrink.
    assert!(matches!(stream.read_frame(), Err(ReadFrameError::Closed)));
    assert_eq!(stream.capacity(), 8192);
    stream.shrink_to_fit();
    assert_eq!(stream.capacity(), 1280);
}

#[test]
fn should_preserve_frames_while_compacting_the_stream_buffer() {
    // 64 frames of 27 bytes: the first read stops inside the 48th frame,
    // which is then shifted to the front.
    let frame = bytes(CODEC12_COMMAND);
    let frame_count = 64;
    let input = frame.repeat(frame_count);
    let mut stream = TeltonikaTcpStream::new(Cursor::new(input));

    for _ in 0..frame_count {
        let FrameView::Gprs(packet) = stream.read_frame().unwrap() else {
            panic!("expected Codec 12")
        };
        assert_eq!(packet.messages().next().unwrap().payload(), b"getinfo");
    }
    assert!(matches!(stream.read_frame(), Err(ReadFrameError::Closed)));
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

    stream.write_avl_nack().unwrap();
    assert_eq!(stream.get_ref().flush_count, 4);

    let output = stream.into_inner().output;
    assert_eq!(&output[..5], &[1, 0, 0, 0, 2]);
    assert_eq!(&output[5..32], bytes(CODEC12_COMMAND));
    assert_eq!(&output[32..], &[0; 4]);
}

#[test]
fn should_not_write_commands_that_cant_form_a_frame() {
    let mut stream = TeltonikaTcpStream::new(ObservedWriter::default());
    let none: [&str; 0] = [];
    assert!(matches!(
        stream.write_commands(&none),
        Err(WriteCommandError::Encode(
            nom_teltonika::encoder::EncodeGprsError::NoMessages
        ))
    ));
    assert!(stream.get_ref().output.is_empty());
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
