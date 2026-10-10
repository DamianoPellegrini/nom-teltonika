use core::fmt;
use std::boxed::Box;
use std::io;
use std::net::SocketAddr;

use crate::decoder::{DatagramError, DecodeDatagramError, take_datagram};
use crate::encoder::encode_udp_ack;
use crate::protocol::{DatagramIds, DatagramView};

/// Size of the receive buffer: larger than any UDP payload, so a datagram is
/// never truncated.
const BUFFER_LEN: usize = 64 * 1024;

/// A UDP socket that receives Teltonika datagrams and sends their
/// acknowledgments.
///
/// One socket can serve many devices: each datagram comes with its source
/// address, and each acknowledgment goes to an explicit destination with the
/// [`DatagramIds`] of the datagram it acknowledges. It never acknowledges on
/// its own, and returns views that borrow its buffer until the next receive;
/// call `evaluate` on a view to keep it longer.
///
/// It has methods for [`std::net::UdpSocket`] and, with the `tokio` feature,
/// `tokio::net::UdpSocket`: no standard trait covers datagram sockets, so
/// each has its own receive and send methods. With another transport, pass
/// each received datagram to [`take_datagram`] and send the bytes of
/// [`encode_udp_ack`] yourself.
///
/// # Examples
///
/// ```no_run
/// use std::net::UdpSocket;
///
/// use nom_teltonika::udp::TeltonikaUdpSocket;
///
/// let mut socket = TeltonikaUdpSocket::new(UdpSocket::bind("0.0.0.0:5001")?);
/// loop {
///     let (datagram, peer) = socket.receive_datagram()?;
///     let ids = datagram.ids();
///     let accepted = datagram.packet().records().len() as u8;
///     // Store the records, then acknowledge them.
///     socket.send_ack_to(peer, ids, accepted)?;
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct TeltonikaUdpSocket<S> {
    socket: S,
    buffer: Box<[u8]>,
}

// `S` is unbounded, as for `TeltonikaTcpStream`: a wrapper over a socket this
// crate has no methods for has only the accessors.
impl<S> TeltonikaUdpSocket<S> {
    /// Creates a wrapper over `socket`.
    ///
    /// Allocates a 64 KiB receive buffer once, larger than any UDP payload,
    /// so a datagram is never truncated and receiving never allocates.
    pub fn new(socket: S) -> Self {
        // TODO: Leave the buffer uninitialized, to skip zeroing it, once
        // `BorrowedBuf` is stable (https://github.com/rust-lang/rust/issues/78485)
        // and the sockets accept it. Tokio's `recv_buf_from` already takes
        // uninitialized memory, but using it here would take an `unsafe`
        // block beyond the one the crate allows.
        Self {
            socket,
            buffer: std::vec![0; BUFFER_LEN].into_boxed_slice(),
        }
    }

    /// Returns a shared reference to the socket.
    pub fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Returns a mutable reference to the socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Returns the socket.
    pub fn into_inner(self) -> S {
        self.socket
    }

    fn datagram(
        &self,
        received: usize,
        peer: SocketAddr,
    ) -> Result<(DatagramView<'_>, SocketAddr), ReceiveDatagramError> {
        let result = take_datagram(&mut &self.buffer[..received]);
        #[cfg(feature = "tracing")]
        match &result {
            Ok(datagram) => tracing::trace!(
                received,
                codec_id = u8::from(datagram.packet().codec()),
                "received UDP datagram"
            ),
            Err(error) => tracing::debug!(%error, received, "invalid UDP datagram"),
        }
        match result {
            Ok(datagram) => Ok((datagram, peer)),
            Err(DecodeDatagramError::NoHeader) => Err(ReceiveDatagramError::NoHeader { peer }),
            Err(DecodeDatagramError::InvalidDatagram { ids, reason }) => {
                Err(ReceiveDatagramError::InvalidDatagram { peer, ids, reason })
            }
        }
    }
}

impl TeltonikaUdpSocket<std::net::UdpSocket> {
    /// Receives the next datagram and its source address.
    ///
    /// The result borrows this socket until the next receive.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiveDatagramError`]. After `NoHeader` or
    /// `InvalidDatagram` nothing is answered and the next datagram can be
    /// received; `InvalidDatagram` carries the source address and the
    /// datagram's IDs, to answer it with [`send_ack_to`](Self::send_ack_to).
    pub fn receive_datagram(
        &mut self,
    ) -> Result<(DatagramView<'_>, SocketAddr), ReceiveDatagramError> {
        let (received, peer) = self.socket.recv_from(&mut self.buffer)?;
        self.datagram(received, peer)
    }

    /// Sends the acknowledgment of a datagram to `peer`.
    ///
    /// Pass the IDs of the datagram and the number of records your
    /// application has accepted.
    ///
    /// # Errors
    ///
    /// Returns the socket's error, or [`io::ErrorKind::WriteZero`] if the
    /// acknowledgment was sent partially.
    pub fn send_ack_to(
        &self,
        peer: SocketAddr,
        ids: DatagramIds,
        accepted_records: u8,
    ) -> io::Result<()> {
        let ack = encode_udp_ack(ids, accepted_records);
        let sent = self.socket.send_to(&ack, peer)?;
        check_sent(sent, ack.len())
    }
}

#[cfg(feature = "tokio")]
impl TeltonikaUdpSocket<tokio::net::UdpSocket> {
    /// Receives the next datagram and its source address.
    ///
    /// Same as [`receive_datagram`](TeltonikaUdpSocket::receive_datagram).
    /// Cancel-safe: a cancelled receive consumes no datagram.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiveDatagramError`], as
    /// [`receive_datagram`](TeltonikaUdpSocket::receive_datagram) does.
    pub async fn receive_datagram_async(
        &mut self,
    ) -> Result<(DatagramView<'_>, SocketAddr), ReceiveDatagramError> {
        let (received, peer) = self.socket.recv_from(&mut self.buffer).await?;
        self.datagram(received, peer)
    }

    /// Sends the acknowledgment of a datagram to `peer`.
    ///
    /// Same as [`send_ack_to`](TeltonikaUdpSocket::send_ack_to). If cancelled,
    /// the acknowledgment may or may not have been sent.
    ///
    /// # Errors
    ///
    /// Returns the socket's error, or [`io::ErrorKind::WriteZero`] if the
    /// acknowledgment was sent partially.
    pub async fn send_ack_to_async(
        &self,
        peer: SocketAddr,
        ids: DatagramIds,
        accepted_records: u8,
    ) -> io::Result<()> {
        let ack = encode_udp_ack(ids, accepted_records);
        let sent = self.socket.send_to(&ack, peer).await?;
        check_sent(sent, ack.len())
    }
}

fn check_sent(sent: usize, len: usize) -> io::Result<()> {
    #[cfg(feature = "tracing")]
    tracing::trace!(sent, "sent UDP acknowledgment");
    if sent == len {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP acknowledgment sent partially",
        ))
    }
}

/// The error returned by [`TeltonikaUdpSocket::receive_datagram`].
///
/// The first two variants are those of [`DecodeDatagramError`], with the
/// address the datagram came from.
#[derive(Debug)]
pub enum ReceiveDatagramError {
    /// The datagram is shorter than its header, so it has no IDs to answer
    /// with: the next one can be received.
    NoHeader {
        /// Address the datagram came from.
        peer: SocketAddr,
    },
    /// The datagram has a header, but is invalid: the next one can be
    /// received.
    ///
    /// Nothing is answered. To have the device send its records again
    /// without waiting for its timeout, acknowledge zero records to `peer`
    /// with `ids`.
    InvalidDatagram {
        /// Address the datagram came from.
        peer: SocketAddr,
        /// The IDs read from the header. They are as trustworthy as the
        /// datagram.
        ids: DatagramIds,
        /// Why the datagram is invalid.
        reason: DatagramError,
    },
    /// The socket failed.
    Io(io::Error),
}

impl From<io::Error> for ReceiveDatagramError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for ReceiveDatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHeader { .. } => f.write_str("UDP datagram is shorter than its header"),
            Self::InvalidDatagram { .. } => f.write_str("invalid UDP datagram"),
            Self::Io(_) => f.write_str("failed to receive a UDP datagram"),
        }
    }
}

impl core::error::Error for ReceiveDatagramError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NoHeader { .. } => None,
            Self::InvalidDatagram { reason, .. } => Some(reason),
            Self::Io(error) => Some(error),
        }
    }
}
