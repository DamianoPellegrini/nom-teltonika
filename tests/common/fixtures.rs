//! Protocol fixtures, shared by the integration tests (through `common`)
//! and by the unit tests in `src` (through `crate::fixtures`).

#![allow(dead_code)]

// Fixtures come from https://wiki.teltonika-gps.com/view/Codec, accessed 2026-09-24, unless
// noted otherwise; each names its section.

/// Codec 8 frame, one record with five IO elements: "Codec 8 > Codec 8
/// protocol sending over TCP > Examples > 1st example".
pub const CODEC8: &str = "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF";
/// Codec 8 Extended frame, one record with five IO elements and NX = 0,
/// from the example in "Codec 8 Extended > Codec 8 Extended protocol
/// sending over TCP".
pub const CODEC8_EXTENDED: &str = "000000000000004A8E010000016B412CEE000100000000000000000000000000000000010005000100010100010011001D00010010015E2C880002000B000000003544C87A000E000000001DD7E06A00000100002994";
/// Codec 16 frame, two records, from the example in "Codec 16 > Codec 16
/// protocol sending over TCP". The example's parsed table says priority
/// `01`, but this stream, whose CRC checks out, has `00`; tests follow the
/// stream.
pub const CODEC16: &str = "000000000000005F10020000016BDBC7833000000000000000000000000000000000000B05040200010000030002000B00270042563A00000000016BDBC7871800000000000000000000000000000000000B05040200010000030002000B00260042563A00000200005FB3";
/// Codec 12 `getinfo` command: "Codec 12 > GPRS commands examples > 1st
/// example".
pub const CODEC12_COMMAND: &str = "000000000000000F0C010500000007676574696E666F0100004312";
/// Codec 8 UDP datagram, one record: "Codec 8 > Codec8 protocol sending
/// over UDP > Example".
pub const UDP_CODEC8: &str = "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001";
/// Codec 8 frame, one record with minimal IO: "Codec 8 > Codec 8 protocol
/// sending over TCP > Examples > 2nd example".
pub const CODEC8_SINGLE_RECORD_ALT: &str = "000000000000002808010000016B40D9AD80010000000000000000000000000000000103021503010101425E100000010000F22A";
/// Codec 8 frame, two records: "Codec 8 > Codec 8 protocol sending over
/// TCP > Examples > 3rd example".
pub const CODEC8_TWO_RECORDS: &str = "000000000000004308020000016B40D57B480100000000000000000000000000000001010101000000000000016B40D5C198010000000000000000000000000000000101010101000000020000252C";
/// Codec 12 `getio` command: "Codec 12 > GPRS commands examples > 2nd
/// example".
pub const CODEC12_GETIO_COMMAND: &str = "000000000000000D0C010500000005676574696F01000000CB";
/// Codec 12 device response to `getinfo`: "Codec 12 > GPRS commands
/// examples > 1st example".
pub const CODEC12_GETINFO_RESPONSE: &str = "00000000000000900C010600000088494E493A323031392F372F323220373A3232205254433A323031392F372F323220373A3533205253543A32204552523A312053523A302042523A302043463A302046473A3020464C3A302054553A302F302055543A3020534D533A30204E4F4750533A303A3330204750533A31205341543A302052533A332052463A36352053463A31204D443A30010000C78F";
/// Codec 12 device response to `getio`: "Codec 12 > GPRS commands
/// examples > 2nd example".
pub const CODEC12_GETIO_RESPONSE: &str = "00000000000000370C01060000002F4449313A31204449323A30204449333A302041494E313A302041494E323A313639323420444F313A3020444F323A3101000066E3";
/// Decodes a hexadecimal fixture.
pub fn bytes(value: &str) -> std::vec::Vec<u8> {
    hex::decode(value).unwrap()
}

/// Returns the data field of a TCP frame, from the codec ID to the second
/// count: what follows the 8-byte header and precedes the 4-byte CRC.
pub fn data_field(frame: &[u8]) -> &[u8] {
    &frame[8..frame.len() - 4]
}
