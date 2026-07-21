use std::{error::Error, fmt, io, net::SocketAddr};

use crate::{Limits, ParseError, UdpDatagram, encode_udp_ack, parse_udp_datagram_with_limits};

#[derive(Debug)]
#[non_exhaustive]
pub enum UdpSocketError {
    Truncated {
        received_at_least: usize,
        limit: usize,
    },
    Parse(ParseError),
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

pub struct TeltonikaUdpSocket<S> {
    socket: S,
    limits: Limits,
    receive: Vec<u8>,
}

impl<S> TeltonikaUdpSocket<S> {
    pub fn new(socket: S) -> Self {
        Self::with_limits(socket, Limits::default())
    }

    pub fn with_limits(socket: S, limits: Limits) -> Self {
        Self {
            socket,
            limits,
            receive: vec![0; limits.max_udp_wire_bytes.saturating_add(1)],
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.socket
    }
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }
    pub fn into_inner(self) -> S {
        self.socket
    }
}

impl TeltonikaUdpSocket<std::net::UdpSocket> {
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
                reason: crate::RejectionReason::TrailingData,
            }));
        }
        Ok((parsed.value, source))
    }

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
                reason: crate::RejectionReason::TrailingData,
            }));
        }
        Ok((parsed.value, source))
    }

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
