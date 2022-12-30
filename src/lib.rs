#![doc = include_str!("../README.md")]
mod protocol;
pub mod parser;

pub use protocol::*;

/// IBM CRC16 Algorithm
/// 
/// Uses 0xA001 polynomial
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= byte as u16;
        for _bit in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= 0xA001;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16() {
        let input = hex::decode(
            "08010000016B40D9AD80010000000000000000000000000000000103021503010101425E10000001",
        )
        .unwrap();
        assert_eq!(crc16(&input), 0x0000F22A);
    }
}
