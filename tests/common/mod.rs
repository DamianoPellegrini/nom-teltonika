#![allow(dead_code)]

pub mod strategies;

use std::io::{self, Cursor, Read};

use nom_teltonika::encoder::crc16;

/// Byte-identical to `tests/c8example1.bin`, the reference packet this test
/// suite was originally built from.
pub const CODEC8: &str = "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF";
pub const CODEC8_EXTENDED: &str = "000000000000004A8E010000016B412CEE000100000000000000000000000000000000010005000100010100010011001D00010010015E2C880002000B000000003544C87A000E000000001DD7E06A00000100002994";
pub const CODEC16: &str = "000000000000005F10020000016BDBC7833000000000000000000000000000000000000B05040200010000030002000B00270042563A00000000016BDBC7871800000000000000000000000000000000000B05040200010000030002000B00260042563A00000200005FB3";
pub const CODEC12_COMMAND: &str = "000000000000000F0C010500000007676574696E666F0100004312";
pub const UDP_CODEC8: &str = "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001";
/// Official Teltonika example #2 (single record, minimal IO) — verified live
/// at <https://wiki.teltonika-gps.com/view/Codec>, "AVL data packet" section.
pub const CODEC8_SINGLE_RECORD_ALT: &str = "000000000000002808010000016B40D9AD80010000000000000000000000000000000103021503010101425E100000010000F22A";
/// Official Teltonika example #3 (two records) — verified live at
/// <https://wiki.teltonika-gps.com/view/Codec>, "AVL data packet" section.
pub const CODEC8_TWO_RECORDS: &str = "000000000000004308020000016B40D57B480100000000000000000000000000000001010101000000000000016B40D5C198010000000000000000000000000000000101010101000000020000252C";
/// Official `getio` Codec 12 command example from
/// <https://wiki.teltonika-gps.com/view/Codec>, "GPRS commands examples".
pub const CODEC12_GETIO_COMMAND: &str = "000000000000000D0C010500000005676574696F01000000CB";
/// Official device response to the `getinfo` command from
/// <https://wiki.teltonika-gps.com/view/Codec>, "GPRS commands examples".
pub const CODEC12_GETINFO_RESPONSE: &str = "00000000000000900C010600000088494E493A323031392F372F323220373A3232205254433A323031392F372F323220373A3533205253543A32204552523A312053523A302042523A302043463A302046473A3020464C3A302054553A302F302055543A3020534D533A30204E4F4750533A303A3330204750533A31205341543A302052533A332052463A36352053463A31204D443A30010000C78F";
/// Official device response to the `getio` command from
/// <https://wiki.teltonika-gps.com/view/Codec>, "GPRS commands examples".
pub const CODEC12_GETIO_RESPONSE: &str = "00000000000000370C01060000002F4449313A31204449323A30204449333A302041494E313A302041494E323A313639323420444F313A3020444F323A3101000066E3";
/// Command text sent every 10 seconds by the independent Node.js device
/// simulator <https://github.com/aymen2709/teltonika-client>, captured by
/// running that project's `client.js` against this crate's TCP server.
/// Only this payload text is third-party; the wire frame around it is
/// produced by this crate's own [`nom_teltonika::encoder::encode_codec12_command`],
/// so decoding it exercises an own-encoder round-trip over a real-world
/// payload, not a decode of third-party bytes.
pub const MEDISAIL_COMMAND_TEXT: &str = "MEDISAIL&1=2661.00&2=324300.00&3=0&4=0&5=355000.00&6=358.10&7=13.40&8=53.30&9=12467683.00&10=48500.00&11=22000.00&12=51&13=26&14=344500.00&15=394.60&20=4.50&21=-1000000000.00&22=-1000000000.00&23=4.62&24=6.07&25=278.35&26=293.35&27=101300.00&28=278.35&29=-1000000000.00&30=56.80&31=42.00&32=101300.00&33=278.35&34=-0.10&39=9.13&40=6.36&42=1&AYMEN";

pub fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

pub fn repair_crc(frame: &mut [u8]) {
    let data_length = u32::from_be_bytes(frame[4..8].try_into().unwrap()) as usize;
    let data_end = 8 + data_length;
    let checksum = crc16(&frame[8..data_end]);
    frame[data_end..data_end + 4].copy_from_slice(&(checksum as u32).to_be_bytes());
}

pub fn tcp_frame_from_data(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(data.len() + 12);
    frame.extend_from_slice(&[0; 4]);
    frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
    frame.extend_from_slice(data);
    frame.extend_from_slice(&(crc16(data) as u32).to_be_bytes());
    frame
}

pub struct ChunkedReader {
    pub inner: Cursor<Vec<u8>>,
    pub chunk: usize,
}

impl Read for ChunkedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let length = output.len().min(self.chunk);
        self.inner.read(&mut output[..length])
    }
}
