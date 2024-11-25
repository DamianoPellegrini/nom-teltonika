use std::io::Cursor;

use nom_teltonika::TeltonikaStream;

fn main() {
    // Write getinfo command to the device
    let mut stream = TeltonikaStream::new(Cursor::new(Vec::new()));
    stream.write_command("getinfo").expect("Write failed");
    let mut buffer = stream.into_inner().into_inner();

    // Compare with actual buffer that should be sent
    let cmp = hex::decode("000000000000000F0C010500000007676574696E666F0100004312").unwrap();
    assert_eq!(cmp, buffer);

    // Read back as if it was a response
    buffer = hex::decode("000000000000000F0C010600000007676574696E666F0100008017").unwrap();
    stream = TeltonikaStream::new(Cursor::new(buffer));
    let frame = stream.read_frame().unwrap().unwrap_gprs();
    println!("{frame:#?}");
}
