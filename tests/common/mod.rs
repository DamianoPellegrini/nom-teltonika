#![allow(dead_code)]

mod fixtures;
pub mod strategies;

#[allow(unused_imports)]
pub use fixtures::*;

use std::io::{self, Cursor, Read};

use nom_teltonika::crc16;

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
