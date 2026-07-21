#![cfg(feature = "serde")]

use nom_teltonika::{
    parser::{Limits, parse_tcp_frame},
    protocol::Imei,
};

#[test]
fn should_serialize_wire_model_when_serde_is_enabled() {
    let input = hex::decode("000000000000000F0C010500000007676574696E666F0100004312").unwrap();
    let frame = parse_tcp_frame(&input).unwrap().value;
    let value = serde_json::to_value(frame).unwrap();
    assert_eq!(
        value["Codec12"]["message"]["Command"][0],
        serde_json::json!([103, 101, 116, 105, 110, 102, 111])
    );
}

#[test]
fn should_reject_invalid_validated_values_when_deserializing() {
    assert!(serde_json::from_str::<Imei>("\"12345678901234x\"").is_err());
    let invalid_limits = r#"{
        "max_avl_wire_bytes": 0,
        "max_codec12_wire_bytes": 65536,
        "max_udp_wire_bytes": 2048
    }"#;
    assert!(serde_json::from_str::<Limits>(invalid_limits).is_err());
}
