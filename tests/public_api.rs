use nom_teltonika::{decoder, encoder, protocol, stream, udp};

#[test]
fn public_api_is_grouped_by_responsibility() {
    let _decode: fn(&[u8]) -> Result<decoder::Decoded<protocol::Frame>, decoder::DecodeError> =
        decoder::decode_tcp_frame;
    let _decode_udp: fn(&[u8]) -> Result<protocol::UdpDatagram, decoder::UdpDecodeError> =
        decoder::decode_udp_datagram;
    let _encode: fn(u32) -> [u8; 4] = encoder::encode_avl_ack;

    fn assert_public_types<S>(
        _: Option<stream::TeltonikaTcpStream<S>>,
        _: Option<udp::TeltonikaUdpSocket<S>>,
    ) {
    }

    assert_public_types::<std::io::Cursor<Vec<u8>>>(None, None);
}
