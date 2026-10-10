#![cfg(all(feature = "serde", feature = "alloc"))]

use nom_teltonika::{decoder::take_frame, protocol::Imei};

#[test]
fn should_serialize_values_as_sent_when_serde_is_enabled() {
    let input = hex::decode("000000000000000F0C010500000007676574696E666F0100004312").unwrap();
    let frame = take_frame(&mut &input[..]).unwrap();
    let value = serde_json::to_value(frame).unwrap();
    assert_eq!(
        value["Gprs"]["messages"][0],
        serde_json::json!({
            "kind": "Command",
            "payload": [103, 101, 116, 105, 110, 102, 111],
        })
    );
}

#[test]
fn should_reject_invalid_imei_when_deserializing() {
    // Non-ASCII, not a wrong digit: an IMEI is only required to be ASCII.
    assert!(serde_json::from_str::<Imei>("\"1234567890123é\"").is_err());
    assert_eq!(
        serde_json::from_str::<Imei>("\"356307042441013\"")
            .unwrap()
            .as_str(),
        "356307042441013"
    );
}
