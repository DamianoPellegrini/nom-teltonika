#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = nom_teltonika::parse_tcp_frame(input);
    let _ = nom_teltonika::parse_udp_datagram(input);
    let _ = nom_teltonika::parse_imei(input);
});
