use std::io;

#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{AVLDatagram, Codec, TeltonikaFrame};

const DEFAULT_IMEI_BUF_CAPACITY: usize = 128;
const DEFAULT_PACKET_BUF_CAPACITY: usize = 2048;

/// A wrapper around a Stream for reading and writing Teltonika GPS module data.
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

impl<S: io::Read + io::Write> TeltonikaStream<S> {
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
    /// If no bytes are read from the stream, it either means that a command response of length 0 has been sent or that the stream has been closed.
    /// If the frame cannot be parsed, an error kind of [`std::io::ErrorKind::InvalidData`] is returned.
    pub fn read_frame(&mut self) -> io::Result<TeltonikaFrame> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.packet_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut revc_buf = vec![0u8; self.packet_buf_capacity];
            let bytes_read = self.inner.read(&mut revc_buf)?;

            // Since teltonika devices can send 0 bytes command responses this needs to be removed
            // if bytes_read == 0 {
            //     return Err(io::Error::new(
            //         io::ErrorKind::ConnectionReset,
            //         "Connection closed",
            //     ));
            // }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let frame_parser_result = crate::parser::tcp_frame(&parse_buf[..]);

            match frame_parser_result {
                Ok((_, frame)) => {
                    return Ok(frame);
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
        self.inner.flush()
    }

    /// Writes an IMEI denial signal to the stream.
    pub fn write_imei_denial(&mut self) -> io::Result<()> {
        self.inner.write_all(&0u8.to_be_bytes())?;
        self.inner.flush()
    }

    /// Writes a frame ACK (acknowledgment) to the stream.
    /// If `ack` is `None`, writes a zero value.
    pub fn write_frame_ack(&mut self, frame: Option<&TeltonikaFrame>) -> io::Result<()> {
        let ack: u32 = frame
            .map(|v| match v {
                TeltonikaFrame::AVL(avlframe) => avlframe.records.len() as u32,
                TeltonikaFrame::GPRS(gprsframe) => gprsframe.command_responses.len() as u32,
            })
            .unwrap_or(0);
        self.inner.write_all(&ack.to_be_bytes())?;
        self.inner.flush()
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
        self.inner.flush()
    }

    /// Writes a series of commands to the stream.
    pub fn write_commands(&mut self, commands: &[&str]) -> io::Result<()> {
        let data_size: usize = std::mem::size_of::<Codec>() + // codec
        						std::mem::size_of::<u8>() + // command qty1
              					std::mem::size_of::<u8>() + // command type
                   				commands
                       				.iter()
                           			.fold(0, |acc, e| acc + (std::mem::size_of::<u32>() + e.bytes().len())) + // command size + command string
                       			std::mem::size_of::<u8>(); // command qty2

        let header_size = std::mem::size_of::<u32>() + // preamble
        							std::mem::size_of::<u32>(); // data size
        let buffer_size = header_size + data_size + std::mem::size_of::<u32>(); // CRC 16

        let mut commands_buffer = Vec::with_capacity(buffer_size);
        commands_buffer.extend([0x00, 0x00, 0x00, 0x00].iter()); // preamble
        commands_buffer.extend((data_size as u32).to_be_bytes().iter()); // data size
        commands_buffer.push(Codec::C12.into()); // codec
        commands_buffer.push(commands.len() as u8); // Qty1
        commands_buffer.push(0x05u8); // Command type
        commands_buffer.extend(commands.iter().flat_map(|command| {
            let mut command_buffer =
                Vec::with_capacity(std::mem::size_of::<u32>() + command.bytes().len());

            command_buffer.extend((command.bytes().len() as u32).to_be_bytes());
            command_buffer.extend(command.bytes()); // no call to to_be_bytes needed because it writes single bytes

            command_buffer
        }));
        commands_buffer.push(commands.len() as u8); // Qty2
        commands_buffer.extend(
            (crate::crc16(&commands_buffer[header_size..]) as u32)
                .to_be_bytes()
                .iter(),
        ); // crc 16

        self.inner.write_all(&commands_buffer)?;
        self.inner.flush()
    }

    /// Writes a single command to the stream.
    pub fn write_command(&mut self, command: &str) -> io::Result<()> {
        self.write_commands(&[command])
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
    pub async fn read_frame_async(&mut self) -> io::Result<TeltonikaFrame> {
        let mut parse_buf: Vec<u8> = Vec::with_capacity(self.packet_buf_capacity * 2);

        // Read bytes until they are enough
        loop {
            let mut revc_buf = vec![0u8; self.packet_buf_capacity];
            let bytes_read = self.inner.read(&mut revc_buf).await?;

            // Since teltonika devices can send 0 bytes command responses this needs to be removed
            // if bytes_read == 0 {
            //     return Err(io::Error::new(
            //         io::ErrorKind::ConnectionReset,
            //         "Connection closed",
            //     ));
            // }

            parse_buf.extend_from_slice(&revc_buf[..bytes_read]);

            let frame_parser_result = crate::parser::tcp_frame(&parse_buf[..]);

            match frame_parser_result {
                Ok((_, frame)) => {
                    return Ok(frame);
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
        self.inner.flush().await
    }

    /// Writes an IMEI denial signal to the stream.
    pub async fn write_imei_denial_async(&mut self) -> io::Result<()> {
        self.inner.write_all(&0u8.to_be_bytes()).await?;
        self.inner.flush().await
    }

    /// Writes a frame ACK (acknowledgment) to the stream.
    /// If `ack` is `None`, writes a zero value.
    pub async fn write_frame_ack_async(
        &mut self,
        frame: Option<&TeltonikaFrame>,
    ) -> io::Result<()> {
        let ack: u32 = frame
            .map(|v| match v {
                TeltonikaFrame::AVL(avlframe) => avlframe.records.len() as u32,
                TeltonikaFrame::GPRS(gprsframe) => gprsframe.command_responses.len() as u32,
            })
            .unwrap_or(0);
        self.inner.write_all(&ack.to_be_bytes()).await?;
        self.inner.flush().await
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
        self.inner.flush().await
    }

    /// Writes a series of commands to the stream.
    pub async fn write_commands_async(&mut self, commands: &[&str]) -> io::Result<()> {
        let header_size = std::mem::size_of::<u32>() + // preamble
        							std::mem::size_of::<u32>(); // data size

        let data_size: usize = std::mem::size_of::<Codec>() + // codec
        						std::mem::size_of::<u8>() + // command qty1
              					std::mem::size_of::<u8>() + // command type
                   				commands
                       				.iter()
                           			.fold(0, |acc, e| acc + (std::mem::size_of::<u32>() + e.bytes().len())) + // command size + command string
                       			std::mem::size_of::<u8>(); // command qty2

        let buffer_size = header_size + data_size + std::mem::size_of::<u32>(); // CRC 16

        let mut commands_buffer = Vec::with_capacity(buffer_size);
        commands_buffer.extend([0x00, 0x00, 0x00, 0x00].iter()); // preamble
        commands_buffer.extend((data_size as u32).to_be_bytes().iter()); // data size
        commands_buffer.push(Codec::C12.into()); // codec
        commands_buffer.push(commands.len() as u8); // Qty1
        commands_buffer.push(0x05u8); // Command type
        commands_buffer.extend(commands.iter().flat_map(|command| {
            let mut command_buffer =
                Vec::with_capacity(std::mem::size_of::<u32>() + command.bytes().len());

            command_buffer.extend((command.bytes().len() as u32).to_be_bytes());
            command_buffer.extend(command.bytes()); // no call to to_be_bytes needed because it writes single bytes

            command_buffer
        }));
        commands_buffer.push(commands.len() as u8); // Qty2
        commands_buffer.extend(
            (crate::crc16(&commands_buffer[header_size..]) as u32)
                .to_be_bytes()
                .iter(),
        ); // crc 16

        self.inner.write_all(&commands_buffer).await?;
        self.inner.flush().await
    }

    /// Writes a single command to the stream.
    pub async fn write_command_async(&mut self, command: &str) -> io::Result<()> {
        self.write_commands_async(&[command]).await
    }
}
