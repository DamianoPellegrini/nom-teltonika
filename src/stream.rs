use std::io::{self, Read, Write};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{crc16, AVLDatagram, AVLFrame};

const DEFAULT_IMEI_BUF_CAPACITY: usize = 128;
const DEFAULT_PACKET_BUF_CAPACITY: usize = 2048;

/// A wrapper around a TCP stream for reading and writing Teltonika GPS module data.
pub struct TeltonikaStream<S> {
    inner: S,
    imei_buf_capacity: usize,
    packet_buf_capacity: usize,
}

impl<S> TeltonikaStream<S> {
    /// Creates a new [`TeltonikaStream`] from an existing TCP stream.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            imei_buf_capacity: DEFAULT_IMEI_BUF_CAPACITY,
            packet_buf_capacity: DEFAULT_PACKET_BUF_CAPACITY,
        }
    }

    /// Creates a new [`TeltonikaStream`] with custom buffer capacities.
    pub fn with_capacity(inner: S, imei_buf_capacity: usize, packet_buf_capacity: usize) -> Self {
        let mut stream = Self::new(inner);
        stream.imei_buf_capacity = imei_buf_capacity;
        stream.packet_buf_capacity = packet_buf_capacity;
        stream
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Read + Write> TeltonikaStream<S> {
    /// Reads the IMEI (International Mobile Equipment Identity) from the stream.
    /// Returns the IMEI as a string.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error variant will be returned as in [`Read::read`].
    ///
    /// If no bytes are read from the stream, an error kind of [`std::io::ErrorKind::ConnectionReset`] is returned.
    /// If the IMEI cannot be parsed, an error kind of [`std::io::ErrorKind::InvalidData`] is returned.
    pub fn read_imei(&mut self) -> io::Result<String> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.imei_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut recv_buf = vec![0u8; self.imei_buf_capacity];
            let bytes_read = self.inner.read(&mut recv_buf[..])?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&recv_buf[..bytes_read]);

            let frame_parser_result = crate::parser::imei(&parse_buf[..]);

            match frame_parser_result {
                Ok((_, imei)) => return Ok(imei),
                Err(nom::Err::Incomplete(_)) => continue,
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }

    /// Reads an AVLFrame from the stream.
    /// Returns the parsed AVLFrame.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error variant will be returned as in [`Read::read`].
    ///
    /// If no bytes are read from the stream, an error kind of [`std::io::ErrorKind::ConnectionReset`] is returned.
    /// If the frame cannot be parsed, an error kind of [`std::io::ErrorKind::InvalidData`] is returned.
    pub fn read_frame(&mut self) -> io::Result<AVLFrame> {
        self.read_frame_and_bytes().map(|(frame, _)| frame)
    }

    /// Functions the same a read_frame but also returns the raw bytes read
    pub fn read_frame_and_bytes(&mut self) -> io::Result<(AVLFrame, Vec<u8>)> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.packet_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut revc_buf = vec![0u8; self.packet_buf_capacity];
            let bytes_read = self.inner.read(&mut revc_buf)?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let frame_parser_result = crate::parser::tcp_frame(&parse_buf[..]);

            match frame_parser_result {
                Ok((_, frame)) => {
                    return Ok((frame, parse_buf));
                }
                Err(nom::Err::Incomplete(_)) => {
                    continue;
                }
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }

    pub fn read_datagram(&mut self) -> io::Result<AVLDatagram> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.packet_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut revc_buf = vec![0u8; self.packet_buf_capacity];
            let bytes_read = self.inner.read(&mut revc_buf)?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let datagram_parser_result = crate::parser::udp_datagram(&parse_buf[..]);

            match datagram_parser_result {
                Ok((_, datagram)) => {
                    return Ok(datagram);
                }
                Err(nom::Err::Incomplete(_)) => {
                    continue;
                }
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }

    /// Writes an IMEI approval signal to the stream.
    pub fn write_imei_approval(&mut self) -> io::Result<()> {
        self.inner.write_all(&1u8.to_be_bytes())?;
        self.inner.flush()?;
        Ok(())
    }

    /// Writes an IMEI denial signal to the stream.
    pub fn write_imei_denial(&mut self) -> io::Result<()> {
        self.inner.write_all(&0u8.to_be_bytes())?;
        self.inner.flush()?;
        Ok(())
    }

    /// Writes a frame ACK (acknowledgment) to the stream.
    /// If `ack` is `None`, writes a zero value.
    pub fn write_frame_ack(&mut self, frame: Option<&AVLFrame>) -> io::Result<()> {
        let ack: u32 = frame.map(|v| v.records.len() as u32).unwrap_or(0);
        self.inner.write_all(&ack.to_be_bytes())?;
        self.inner.flush()?;
        Ok(())
    }

    pub fn write_datagram_ack(&mut self, datagram: Option<&AVLDatagram>) -> io::Result<()> {
        let (length, packet_id, avl_packet_id, ack) = match datagram {
            Some(datagram) => (
                datagram.records.len() as u16,
                datagram.packet_id,
                datagram.avl_packet_id,
                datagram.records.len() as u32,
            ),
            None => (0, 0, 0, 0),
        };
        self.inner.write_all(&length.to_be_bytes())?;
        self.inner.write_all(&packet_id.to_be_bytes())?;
        self.inner.write_all(b"\x01")?; // Non usable-byte
        self.inner.write_all(&avl_packet_id.to_be_bytes())?;
        self.inner.write_all(&ack.to_be_bytes())?;
        self.inner.flush()?;
        Ok(())
    }

    pub fn write_command(&mut self, command: impl AsRef<[u8]>) -> io::Result<()> {
        let command = build_command_codec12(command);

        self.inner.write_all(&command)?;
        self.inner.flush()?;

        Ok(())
    }

    pub fn read_command(&mut self) -> io::Result<Vec<u8>> {
        let mut parse_buf: Vec<u8> = Vec::new();

        // Read bytes until they are enough
        loop {
            let mut revc_buf = Vec::new();
            let bytes_read = self.inner.read(&mut revc_buf)?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let command_parser_result = crate::parser::command_response(&parse_buf[..]);

            match command_parser_result {
                Ok((_, command)) => {
                    return Ok(command.into());
                }
                Err(nom::Err::Incomplete(_)) => {
                    continue;
                }
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }
}

#[cfg(feature = "tokio")]
impl<S: AsyncReadExt + AsyncWriteExt + Unpin> TeltonikaStream<S> {
    /// Reads the IMEI (International Mobile Equipment Identity) from the stream.
    /// Returns the IMEI as a string.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error variant will be returned as in [`Read::read`].
    ///
    /// If no bytes are read from the stream, an error kind of [`std::io::ErrorKind::ConnectionReset`] is returned.
    /// If the IMEI cannot be parsed, an error kind of [`std::io::ErrorKind::InvalidData`] is returned.
    pub async fn read_imei_async(&mut self) -> io::Result<String> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.imei_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut recv_buf = vec![0u8; self.imei_buf_capacity];
            let bytes_read = self.inner.read(&mut recv_buf[..]).await?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&recv_buf[..bytes_read]);

            let frame_parser_result = crate::parser::imei(&parse_buf[..]);

            match frame_parser_result {
                Ok((_, imei)) => return Ok(imei),
                Err(nom::Err::Incomplete(_)) => continue,
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }

    /// Reads an AVLFrame from the stream.
    /// Returns the parsed AVLFrame.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error variant will be returned as in [`Read::read`].
    ///
    /// If no bytes are read from the stream, an error kind of [`std::io::ErrorKind::ConnectionReset`] is returned.
    /// If the frame cannot be parsed, an error kind of [`std::io::ErrorKind::InvalidData`] is returned.
    pub async fn read_frame_async(&mut self) -> io::Result<AVLFrame> {
        self.read_frame_and_bytes_async()
            .await
            .map(|(frame, _)| frame)
    }

    /// Functions the same a read_frame but also returns the raw bytes read
    pub async fn read_frame_and_bytes_async(&mut self) -> io::Result<(AVLFrame, Vec<u8>)> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.packet_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut revc_buf = vec![0u8; self.packet_buf_capacity];
            let bytes_read = self.inner.read(&mut revc_buf).await?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let frame_parser_result = crate::parser::tcp_frame(&parse_buf[..]);

            match frame_parser_result {
                Ok((_, frame)) => {
                    return Ok((frame, parse_buf));
                }
                Err(nom::Err::Incomplete(_)) => {
                    continue;
                }
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }

    pub async fn read_datagram_async(&mut self) -> io::Result<AVLDatagram> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.packet_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut revc_buf = vec![0u8; self.packet_buf_capacity];
            let bytes_read = self.inner.read(&mut revc_buf).await?;
            println!("Receive buf: {:?}", revc_buf);
            println!("Bytes read: {:?}", bytes_read);

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let datagram_parser_result = crate::parser::udp_datagram(&parse_buf[..]);

            match datagram_parser_result {
                Ok((_, datagram)) => {
                    return Ok(datagram);
                }
                Err(nom::Err::Incomplete(_)) => {
                    continue;
                }
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }

    /// Writes an IMEI approval signal to the stream.
    pub async fn write_imei_approval_async(&mut self) -> io::Result<()> {
        self.inner.write_all(&1u8.to_be_bytes()).await?;
        self.inner.flush().await?;
        Ok(())
    }

    /// Writes an IMEI denial signal to the stream.
    pub async fn write_imei_denial_async(&mut self) -> io::Result<()> {
        self.inner.write_all(&0u8.to_be_bytes()).await?;
        self.inner.flush().await?;
        Ok(())
    }

    /// Writes a frame ACK (acknowledgment) to the stream.
    /// If `ack` is `None`, writes a zero value.
    pub async fn write_frame_ack_async(&mut self, frame: Option<&AVLFrame>) -> io::Result<()> {
        let ack: u32 = frame.map(|v| v.records.len() as u32).unwrap_or(0);
        self.inner.write_all(&ack.to_be_bytes()).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn write_datagram_ack_async(
        &mut self,
        datagram: Option<&AVLDatagram>,
    ) -> io::Result<()> {
        let (length, packet_id, avl_packet_id, ack) = match datagram {
            Some(datagram) => (
                datagram.records.len() as u16,
                datagram.packet_id,
                datagram.avl_packet_id,
                datagram.records.len() as u32,
            ),
            None => (0, 0, 0, 0),
        };
        self.inner.write_all(&length.to_be_bytes()).await?;
        self.inner.write_all(&packet_id.to_be_bytes()).await?;
        self.inner.write_all(b"\x01").await?; // Non usable-byte
        self.inner.write_all(&avl_packet_id.to_be_bytes()).await?;
        self.inner.write_all(&ack.to_be_bytes()).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn write_command_async(&mut self, command: impl AsRef<[u8]>) -> io::Result<()> {
        let command = build_command_codec12(command);

        println!("Command being sent: {:?}", command);
        self.inner.write_all(&command).await?;
        self.inner.flush().await?;

        Ok(())
    }

    pub async fn read_command_async(&mut self) -> io::Result<Vec<u8>> {
        let mut parse_buf: Vec<u8> = Vec::new();

        // Read bytes until they are enough
        loop {
            let mut revc_buf = Vec::new();
            let bytes_read = self.inner.read(&mut revc_buf).await?;

            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed",
                ));
            }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);
            println!("Parse Buf: {:?}", parse_buf);

            let command_parser_result = crate::parser::command_response(&parse_buf[..]);

            match command_parser_result {
                Ok((_, command)) => {
                    return Ok(command.into());
                }
                Err(nom::Err::Incomplete(_)) => {
                    continue;
                }
                Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        nom::Err::Failure(nom::error::Error::new(e.input.to_owned(), e.code)),
                    ))
                }
            }
        }
    }
}

// builds a command to a stream using the codec 12 protocol
pub fn build_command_codec12(msg: impl AsRef<[u8]>) -> Vec<u8> {
    let msg = msg.as_ref();
    let msg_len = msg.len();

    let mut command = Vec::with_capacity(20 + msg_len);

    // preamble
    command.extend([0; 4]);

    // data size
    command.extend((8 + msg_len as u32).to_be_bytes());

    // codec id
    command.push(0x0C);

    // command quantity 1
    command.push(0x01);

    // type
    command.push(0x05);

    // command size
    command.extend((msg_len as u32).to_be_bytes());

    // command
    command.extend(msg);

    // command quantity 2
    command.push(0x01);

    // crc
    let crc = crc16(&command[8..]) as u32;
    command.extend(crc.to_be_bytes());

    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn building_commands() {
        assert_eq!(
            build_command_codec12(b"getinfo"),
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x0C, 0x01, 0x05, 0x00, 0x00, 0x00,
                0x07, 0x67, 0x65, 0x74, 0x69, 0x6E, 0x66, 0x6F, 0x01, 0x00, 0x00, 0x43, 0x12
            ]
        );
    }
}
