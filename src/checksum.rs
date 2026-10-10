/// Number of input bytes folded into the CRC per step, and so of lookup
/// tables.
const SLICES: usize = 8;

/// The reflected polynomial of CRC-16/IBM: `0x8005` with its bits reversed.
const POLYNOMIAL: u16 = 0xa001;

/// Lookup tables for [`crc16`], computed at compile time.
///
/// `TABLES[0][byte]` is the CRC of `byte` alone. `TABLES[k][byte]` is the
/// CRC of `byte` followed by `k` zero bytes, which is what lets a step fold
/// [`SLICES`] bytes at once: the bytes of one step don't depend on each
/// other, only on the CRC before them.
static TABLES: [[u16; 256]; SLICES] = tables();

const fn tables() -> [[u16; 256]; SLICES] {
    let mut tables = [[0u16; 256]; SLICES];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ POLYNOMIAL
            };
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }
    let mut slice = 1;
    while slice < SLICES {
        let mut byte = 0;
        while byte < 256 {
            let previous = tables[slice - 1][byte];
            tables[slice][byte] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            byte += 1;
        }
        slice += 1;
    }
    tables
}

/// Computes the CRC-16/IBM checksum of `data`, as sent in Teltonika TCP
/// frames.
///
/// CRC-16/IBM (also known as CRC-16/ARC): polynomial `0x8005` processed
/// least significant bit first (`0xa001` reflected), initial value 0, no
/// final XOR. A TCP frame carries it over its data field, from the codec ID
/// to the second quantity, in a 4-byte field whose upper half is zero.
///
/// The checksum covers every byte of every frame, so it is most of the cost
/// of decoding one. It is computed eight bytes per step from tables built at
/// compile time (4 KiB of read-only data), the "slicing-by-8" method of
/// [Kounavis and Berry]: a bit-by-bit loop takes eight dependent steps per
/// byte, and a single table one dependent lookup per byte, while the eight
/// lookups of a step here are independent of each other.
///
/// Source: <https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols>,
/// section "CRC-16" (accessed 2026-09-24).
///
/// [Kounavis and Berry]: https://doi.org/10.1109/TC.2008.85
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    let mut rest = data;
    while let Some((chunk, tail)) = rest.split_first_chunk::<SLICES>() {
        let [low, high] = crc.to_le_bytes();
        crc = TABLES[7][usize::from(chunk[0] ^ low)]
            ^ TABLES[6][usize::from(chunk[1] ^ high)]
            ^ TABLES[5][usize::from(chunk[2])]
            ^ TABLES[4][usize::from(chunk[3])]
            ^ TABLES[3][usize::from(chunk[4])]
            ^ TABLES[2][usize::from(chunk[5])]
            ^ TABLES[1][usize::from(chunk[6])]
            ^ TABLES[0][usize::from(chunk[7])];
        rest = tail;
    }
    for &byte in rest {
        let [low, high] = crc.to_le_bytes();
        crc = u16::from(high) ^ TABLES[0][usize::from(byte ^ low)];
    }
    crc
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// The definition of CRC-16/IBM, one bit at a time.
    fn bitwise(data: &[u8]) -> u16 {
        let mut crc = 0u16;
        for &byte in data {
            crc ^= u16::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ POLYNOMIAL
                };
            }
        }
        crc
    }

    #[test]
    fn matches_the_check_value_of_the_algorithm() {
        // CRC-16/ARC in the catalogue of parametrised CRC algorithms:
        // https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-arc
        assert_eq!(crc16(b"123456789"), 0xbb3d);
        assert_eq!(crc16(b""), 0);
    }

    #[test]
    fn matches_the_wiki_codec8_example() {
        // "Codec 8 > Examples > 1st example" from
        // https://wiki.teltonika-gps.com/view/Codec (accessed 2026-09-24):
        // data field and its CRC-16, `0000C7CF`.
        let frame = crate::fixtures::bytes(crate::fixtures::CODEC8);
        let data = crate::fixtures::data_field(&frame);
        assert_eq!(crc16(data), 0xc7cf);
    }

    #[test]
    fn matches_the_bitwise_definition_at_every_length() {
        // Lengths on both sides of several steps, so every table and the
        // byte-by-byte tail are used with a nonzero CRC carried in.
        let data: Vec<u8> = (0..4 * SLICES + 3)
            .map(|index| (index * 151 + 7) as u8)
            .collect();
        for len in 0..=data.len() {
            assert_eq!(crc16(&data[..len]), bitwise(&data[..len]), "length {len}");
        }
    }
}
