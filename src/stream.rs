use std::io::{self, Read, Write};

use crate::{AVLDatagram, AVLFrame};

const DEFAULT_IMEI_BUF_CAPACITY: usize = 128;
const DEFAULT_PACKET_BUF_CAPACITY: usize = 2048;

/// A wrapper around a TCP stream for reading and writing Teltonika GPS module data.
pub struct TeltonikaStream<S> {
    inner: S,
    imei_buf_capacity: usize,
    packet_buf_capacity: usize,
}

impl<S: Read + Write> TeltonikaStream<S> {
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

    /// Reads the IMEI (International Mobile Equipment Identity) from the stream.
    /// Returns the IMEI as a string.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error variant will be returned as in [`Read::read`].
    ///
    /// If no bytes are read from the stream, an error king of [`std::io::ErrorKind::ConnectionReset`] is returned.
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

            let packet_parser_result = crate::parser::imei(&parse_buf[..]);

            match packet_parser_result {
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

    /// Reads an AVLPacket from the stream.
    /// Returns the parsed AVLPacket.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error variant will be returned as in [`Read::read`].
    ///
    /// If no bytes are read from the stream, an error king of [`std::io::ErrorKind::ConnectionReset`] is returned.
    /// If the packet cannot be parsed, an error kind of [`std::io::ErrorKind::InvalidData`] is returned.
    pub fn read_frame(&mut self) -> io::Result<AVLFrame> {
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

            let packet_parser_result = crate::parser::tcp_frame(&parse_buf[..]);

            match packet_parser_result {
                Ok((_, packet)) => {
                    return Ok(packet);
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

    /// Writes a packet ACK (acknowledgment) to the stream.
    /// If `ack` is `None`, writes a zero value.
    pub fn write_packet_ack(&mut self, packet: Option<&AVLFrame>) -> io::Result<()> {
        let ack: u32 = packet.map(|v| v.records.len() as u32).unwrap_or(0);
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
}
