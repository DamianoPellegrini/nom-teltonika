use std::io::{self, Read, Write};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{AVLDatagram, AVLFrame};

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
        match self.read_frame_and_bytes() {
            Ok(o) => Ok(o.0),
            Err(e) => Err(e),
        }
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
}
