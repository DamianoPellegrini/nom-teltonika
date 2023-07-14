fn main() {
    // Load file.bin
    let mut file = std::fs::File::open("file.bin").unwrap();
    let mut buffer = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buffer).unwrap();
    // Parse file.bin
    let (_, packet) = nom_teltonika::parser::tcp_frame(&buffer).unwrap();
    println!("{packet:#?}");
}
