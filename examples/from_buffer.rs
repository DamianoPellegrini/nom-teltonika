//! Writes a Codec 12 command and reads a response through in-memory buffers.
//!
//! Run with `cargo run --example from_buffer`.

use std::io::Cursor;

use nom_teltonika::{protocol::FrameView, tcp::TeltonikaTcpStream};

fn main() {
    // Write the getinfo command to the device.
    let mut stream = TeltonikaTcpStream::new(Cursor::new(Vec::new()));
    stream.write_command("getinfo").expect("write failed");
    let buffer = stream.into_inner().into_inner();

    // "Codec 12 > GPRS commands examples", 1st example, from the Teltonika wiki.
    let expected = hex::decode("000000000000000F0C010500000007676574696E666F0100004312").unwrap();
    assert_eq!(buffer, expected);

    // Read back the device's response from the same example.
    let response = hex::decode(
        "00000000000000900C010600000088494E493A323031392F372F323220373A3232205254433A323031392F372F323220373A3533205253543A32204552523A312053523A302042523A302043463A302046473A3020464C3A302054553A302F302055543A3020534D533A30204E4F4750533A303A3330204750533A31205341543A302052533A332052463A36352053463A31204D443A30010000C78F",
    )
    .unwrap();
    let mut stream = TeltonikaTcpStream::new(Cursor::new(response));
    let FrameView::Gprs(packet) = stream.read_frame().expect("read failed") else {
        panic!("expected a Codec 12 response");
    };
    for message in packet.messages() {
        println!("{}", String::from_utf8_lossy(message.payload()));
    }
}
