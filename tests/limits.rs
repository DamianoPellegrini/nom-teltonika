use nom_teltonika::decoder::{LimitsError, TcpLimits, UdpLimits};

#[test]
fn should_expose_documented_defaults_and_operational_minimums() {
    let tcp = TcpLimits::default();
    let udp = UdpLimits::default();

    assert_eq!(tcp.max_avl_frame_bytes(), 1280);
    assert_eq!(tcp.max_codec12_frame_bytes(), 65_536);
    assert_eq!(udp.max_datagram_bytes(), 2048);
    assert!(TcpLimits::new(45, 20).is_ok());
    assert!(UdpLimits::new(56).is_ok());
}

#[test]
fn should_report_diagnostic_values_for_invalid_limits() {
    assert_eq!(
        TcpLimits::new(44, 20),
        Err(LimitsError::AvlFrameTooSmall {
            actual: 44,
            minimum: 45,
        })
    );
    assert_eq!(
        TcpLimits::new(45, 19),
        Err(LimitsError::Codec12FrameTooSmall {
            actual: 19,
            minimum: 20,
        })
    );
    assert_eq!(
        UdpLimits::new(55),
        Err(LimitsError::UdpDatagramTooSmall {
            actual: 55,
            minimum: 56,
        })
    );
    assert!(UdpLimits::new(65_537).is_ok());
    assert_eq!(
        UdpLimits::new(65_538),
        Err(LimitsError::UdpDatagramTooLarge {
            actual: 65_538,
            maximum: 65_537,
        })
    );
}
