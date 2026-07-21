#![allow(dead_code)]

use std::io::{self, Cursor, Read};

use nom_teltonika::parser::crc16;

pub const CODEC8: &str = "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF";
pub const CODEC8_EXTENDED: &str = "000000000000004A8E010000016B412CEE000100000000000000000000000000000000010005000100010100010011001D00010010015E2C880002000B000000003544C87A000E000000001DD7E06A00000100002994";
pub const CODEC16: &str = "000000000000005F10020000016BDBC7833000000000000000000000000000000000000B05040200010000030002000B00270042563A00000000016BDBC7871800000000000000000000000000000000000B05040200010000030002000B00260042563A00000200005FB3";
pub const CODEC12_COMMAND: &str = "000000000000000F0C010500000007676574696E666F0100004312";
pub const UDP_CODEC8: &str = "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001";

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
