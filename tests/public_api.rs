use nom_teltonika::{decoder, encoder, protocol};

#[test]
fn public_api_is_grouped_by_responsibility() {
    let _decode: for<'a> fn(
        &mut &'a [u8],
    ) -> Result<protocol::FrameView<'a>, decoder::DecodeFrameError> = decoder::take_frame;
    let _decode_udp: for<'a> fn(
        &mut &'a [u8],
    ) -> Result<
        protocol::DatagramView<'a>,
        decoder::DecodeDatagramError,
    > = decoder::take_datagram;
    let _take_imei: for<'a> fn(
        &mut &'a [u8],
    ) -> Result<protocol::ImeiView<'a>, decoder::DecodeImeiError> = decoder::take_imei;
    let _encode: fn(u32) -> [u8; 4] = encoder::encode_avl_ack;
}

#[cfg(feature = "std")]
#[test]
fn io_types_are_grouped_by_transport() {
    use nom_teltonika::{tcp, udp};

    fn assert_public_types<S>(
        _: Option<tcp::TeltonikaTcpStream<S>>,
        _: Option<udp::TeltonikaUdpSocket<S>>,
    ) {
    }

    assert_public_types::<std::io::Cursor<Vec<u8>>>(None, None);
}
