use nom_teltonika::{encode, parser, protocol, stream, udp};

#[test]
fn public_api_is_grouped_by_responsibility() {
    let _parse: fn(&[u8]) -> Result<parser::Parsed<protocol::Frame>, parser::ParseError> =
        parser::parse_tcp_frame;
    let _encode: fn(u32) -> [u8; 4] = encode::encode_avl_ack;

    fn assert_public_types<S>(
        _: Option<stream::TeltonikaStream<S>>,
        _: Option<udp::TeltonikaUdpSocket<S>>,
    ) {
    }

    assert_public_types::<std::io::Cursor<Vec<u8>>>(None, None);
}
