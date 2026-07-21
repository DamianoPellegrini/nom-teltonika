#![cfg(feature = "tokio")]

mod common;

use common::*;
use nom_teltonika::{protocol::Frame, stream::*};

#[tokio::test]
async fn should_match_sync_behavior_for_async_stream() {
    use tokio::io::AsyncWriteExt;

    let frame = bytes(CODEC8);
    let (mut sender, receiver) = tokio::io::duplex(frame.len() * 2);
    sender.write_all(&frame).await.unwrap();
    sender.shutdown().await.unwrap();
    let mut stream = TeltonikaStream::new(receiver);
    assert!(matches!(
        stream.read_frame_async().await.unwrap(),
        Frame::Avl(_)
    ));
    assert!(matches!(
        stream.read_frame_async().await,
        Err(StreamReadError::Closed)
    ));
}

#[tokio::test]
async fn should_resume_async_read_after_cancellation() {
    use tokio::io::AsyncWriteExt;

    let frame = bytes(CODEC8);
    let split = 12;
    let (mut sender, receiver) = tokio::io::duplex(frame.len() * 2);
    sender.write_all(&frame[..split]).await.unwrap();
    let mut stream = TeltonikaStream::new(receiver);

    tokio::select! {
        biased;
        result = stream.read_frame_async() => panic!("partial frame completed unexpectedly: {result:?}"),
        _ = tokio::task::yield_now() => {}
    }

    sender.write_all(&frame[split..]).await.unwrap();
    assert!(matches!(
        stream.read_frame_async().await.unwrap(),
        Frame::Avl(_)
    ));
}
