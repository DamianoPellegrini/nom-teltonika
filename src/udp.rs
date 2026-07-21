use std::{error::Error, fmt, io, net::SocketAddr};

use crate::{
    encode_impl::encode_udp_ack,
    parser_impl::parse_udp_datagram_with_limits,
    protocol_impl::{Limits, ParseError, RejectionReason, UdpDatagram},
};

#[derive(Debug)]
#[non_exhaustive]
/// Failure receiving, parsing, or acknowledging a UDP datagram.
pub enum UdpSocketError {
    /// The receive buffer filled past its configured limit, so the datagram was truncated.
    Truncated {
        /// Bytes observed in the limit-plus-one detection buffer.
        received_at_least: usize,
        /// Configured maximum complete UDP datagram size.
        limit: usize,
    },
    /// The received bytes failed UDP channel or enclosed AVL validation.
    Parse(ParseError),
    /// The underlying socket operation failed.
    Io(io::Error),
}

impl fmt::Display for UdpSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                received_at_least,
                limit,
            } => {
                write!(
                    f,
                    "UDP datagram has at least {received_at_least} bytes and exceeds limit {limit}"
                )
            }
            Self::Parse(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for UdpSocketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Truncated { .. } => None,
        }
    }
}

impl From<io::Error> for UdpSocketError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Datagram-aware Teltonika I/O with explicit peer addressing.
///
/// Each receive returns the source address alongside an owned [`UdpDatagram`].
/// Each acknowledgment requires an explicit destination and both packet IDs,
/// preventing accidental cross-device replies when one socket serves many
/// peers. The wrapper does not acknowledge automatically.
pub struct TeltonikaUdpSocket<S> {
    socket: S,
    limits: Limits,
    receive: Vec<u8>,
}

impl<S> TeltonikaUdpSocket<S> {
    /// Wraps a socket using [`Limits::default`].
    pub fn new(socket: S) -> Self {
        Self::with_limits(socket, Limits::default())
    }

    /// Wraps a socket with caller-provided protocol limits.
    ///
    /// The receive buffer is one byte larger than the UDP limit. This sentinel
    /// byte distinguishes a maximum-sized valid datagram from one truncated by
    /// the application buffer.
    pub fn with_limits(socket: S, limits: Limits) -> Self {
        Self {
            socket,
            limits,
            receive: vec![0; limits.max_udp_wire_bytes.saturating_add(1)],
        }
    }

    /// Returns a shared reference to the underlying socket.
    pub fn get_ref(&self) -> &S {
        &self.socket
    }
    /// Returns a mutable reference to the underlying socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }
    /// Extracts the underlying socket.
    pub fn into_inner(self) -> S {
        self.socket
    }
}

impl TeltonikaUdpSocket<std::net::UdpSocket> {
    /// Receives and validates one datagram, preserving its source address.
    ///
    /// Unlike the slice parser, this method requires the complete socket
    /// datagram to contain exactly one Teltonika message.
    ///
    /// # Errors
    ///
    /// Returns [`UdpSocketError::Truncated`] if the datagram exceeds the receive
    /// limit, [`UdpSocketError::Parse`] for protocol failures or trailing bytes,
    /// and [`UdpSocketError::Io`] for socket failures.
    pub fn recv_datagram(&mut self) -> Result<(UdpDatagram, SocketAddr), UdpSocketError> {
        let (received, source) = self.socket.recv_from(&mut self.receive)?;
        if received > self.limits.max_udp_wire_bytes {
            return Err(UdpSocketError::Truncated {
                received_at_least: received,
                limit: self.limits.max_udp_wire_bytes,
            });
        }
        #[cfg(feature = "tracing")]
        tracing::trace!(received, "received UDP datagram");
        let parsed = parse_udp_datagram_with_limits(&self.receive[..received], self.limits)
            .map_err(UdpSocketError::Parse)?;
        if parsed.consumed != received {
            return Err(UdpSocketError::Parse(ParseError::Rejected {
                consumed: received,
                offset: parsed.consumed,
                reason: RejectionReason::TrailingData,
            }));
        }
        Ok((parsed.value, source))
    }

    /// Sends a correlated UDP acknowledgment to an explicit destination.
    ///
    /// Pass both IDs from the received [`UdpDatagram`] and the number of records
    /// accepted by the application. Parsing alone does not imply acceptance.
    pub fn send_ack_to(
        &self,
        destination: SocketAddr,
        channel_packet_id: u16,
        avl_packet_id: u8,
        accepted_records: u8,
    ) -> Result<(), UdpSocketError> {
        let acknowledgment = encode_udp_ack(channel_packet_id, avl_packet_id, accepted_records);
        let sent = self.socket.send_to(&acknowledgment, destination)?;
        if sent != acknowledgment.len() {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "partial UDP acknowledgment").into(),
            );
        }
        #[cfg(feature = "tracing")]
        tracing::trace!(written = sent, "sent UDP acknowledgment");
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl TeltonikaUdpSocket<tokio::net::UdpSocket> {
    /// Asynchronously receives and validates one source-addressed datagram.
    ///
    /// Cancellation does not consume a datagram according to Tokio's
    /// `recv_from` contract. Error behavior otherwise matches
    /// [`Self::recv_datagram`].
    pub async fn recv_datagram_async(
        &mut self,
    ) -> Result<(UdpDatagram, SocketAddr), UdpSocketError> {
        let (received, source) = self.socket.recv_from(&mut self.receive).await?;
        if received > self.limits.max_udp_wire_bytes {
            return Err(UdpSocketError::Truncated {
                received_at_least: received,
                limit: self.limits.max_udp_wire_bytes,
            });
        }
        #[cfg(feature = "tracing")]
        tracing::trace!(received, "received UDP datagram asynchronously");
        let parsed = parse_udp_datagram_with_limits(&self.receive[..received], self.limits)
            .map_err(UdpSocketError::Parse)?;
        if parsed.consumed != received {
            return Err(UdpSocketError::Parse(ParseError::Rejected {
                consumed: received,
                offset: parsed.consumed,
                reason: RejectionReason::TrailingData,
            }));
        }
        Ok((parsed.value, source))
    }

    /// Asynchronously sends a correlated UDP acknowledgment to a destination.
    ///
    /// This operation is not cancellation-safe. Treat cancellation as an
    /// unknown send outcome and rely on application/device retry policy.
    pub async fn send_ack_to_async(
        &self,
        destination: SocketAddr,
        channel_packet_id: u16,
        avl_packet_id: u8,
        accepted_records: u8,
    ) -> Result<(), UdpSocketError> {
        let acknowledgment = encode_udp_ack(channel_packet_id, avl_packet_id, accepted_records);
        let sent = self.socket.send_to(&acknowledgment, destination).await?;
        if sent != acknowledgment.len() {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "partial UDP acknowledgment").into(),
            );
        }
        #[cfg(feature = "tracing")]
        tracing::trace!(written = sent, "sent UDP acknowledgment asynchronously");
        Ok(())
    }
}
