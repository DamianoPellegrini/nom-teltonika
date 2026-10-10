#![cfg(feature = "tokio")]

mod common;

use common::*;
use nom_teltonika::{protocol::FrameView, tcp::*};

#[tokio::test]
async fn should_match_sync_behavior_for_async_stream() {
    use tokio::io::AsyncWriteExt;

    let mut input = bytes("000F333536333037303432343431303133");
    input.extend_from_slice(&bytes(CODEC8));
    let (mut sender, receiver) = tokio::io::duplex(input.len() * 2);
    sender.write_all(&input).await.unwrap();
    sender.shutdown().await.unwrap();
    let mut stream = TeltonikaTcpStream::new(receiver);
    assert_eq!(
        stream.read_imei_async().await.unwrap().as_str(),
        "356307042441013"
    );
    assert!(matches!(
        stream.read_frame_async().await.unwrap(),
        FrameView::Avl(_)
    ));
    assert!(matches!(
        stream.read_frame_async().await,
        Err(ReadFrameError::Closed)
    ));
}

#[tokio::test]
async fn should_resume_async_read_after_cancellation() {
    use tokio::io::AsyncWriteExt;

    let frame = bytes(CODEC8);
    let split = 12;
    let (mut sender, receiver) = tokio::io::duplex(frame.len() * 2);
    sender.write_all(&frame[..split]).await.unwrap();
    let mut stream = TeltonikaTcpStream::new(receiver);

    tokio::select! {
        biased;
        result = stream.read_frame_async() => panic!("partial frame completed unexpectedly: {result:?}"),
        _ = tokio::task::yield_now() => {}
    }

    sender.write_all(&frame[split..]).await.unwrap();
    assert!(matches!(
        stream.read_frame_async().await.unwrap(),
        FrameView::Avl(_)
    ));
}

#[tokio::test]
async fn should_write_async_responses() {
    use tokio::io::AsyncReadExt;

    let (client, mut server) = tokio::io::duplex(64);
    let mut stream = TeltonikaTcpStream::new(client);
    stream.write_imei_approval_async(true).await.unwrap();
    stream.write_avl_ack_async(1).await.unwrap();
    stream.write_avl_nack_async().await.unwrap();
    stream.write_command_async("getinfo").await.unwrap();
    drop(stream);

    let mut output = Vec::new();
    server.read_to_end(&mut output).await.unwrap();
    assert_eq!(&output[..9], &[1, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(&output[9..], bytes(CODEC12_COMMAND));
}
