fn main() {
    // Load file.bin
    let mut file = std::fs::File::open("file.bin").unwrap();
    let mut buffer = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buffer).unwrap();
    // Decode file.bin
    let frame = nom_teltonika::decoder::take_frame(&mut &buffer[..]).unwrap();
    println!("{frame:#?}");
}
