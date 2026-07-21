fn main() {
    // Load file.bin
    let mut file = std::fs::File::open("file.bin").unwrap();
    let mut buffer = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buffer).unwrap();
    // Decode file.bin
    let decoded = nom_teltonika::decoder::decode_tcp_frame(&buffer).unwrap();
    println!("{:#?}", decoded.value);
}
