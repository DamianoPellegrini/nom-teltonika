use std::{error::Error, fmt, io};

use crate::{
    decoder_impl::decode_tcp_frame_with_limits,
    encoder_impl::{
        EncodeError, encode_avl_ack, encode_avl_nack, encode_codec12_commands, encode_imei_approval,
    },
    protocol_impl::{DecodeError, Frame, TcpLimits},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Buffering and protocol limits for [`TeltonikaStream`].
///
/// `read_size` controls each read from the underlying transport; protocol
/// limits, not this chunk size, bound retained frame storage.
pub struct StreamConfig {
    /// Bytes requested from the underlying stream per read; defaults to 4 KiB.
    read_size: usize,
    /// Maximum complete wire sizes accepted by the decoder.
    limits: TcpLimits,
}

impl StreamConfig {
    /// Creates a validated stream configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StreamConfigError`] for a zero read size or invalid limits.
    pub fn new(read_size: usize, limits: TcpLimits) -> Result<Self, StreamConfigError> {
        let config = Self { read_size, limits };
        config.validate()?;
        Ok(config)
    }

    /// Returns the number of bytes requested from the underlying stream per read.
    pub const fn read_size(self) -> usize {
        self.read_size
    }

    /// Returns the maximum complete wire sizes accepted by the decoder.
    pub const fn limits(self) -> TcpLimits {
        self.limits
    }

    fn validate(self) -> Result<(), StreamConfigError> {
        if self.read_size == 0 {
            return Err(StreamConfigError::ZeroReadSize);
        }
        Ok(())
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            read_size: 4 * 1024,
            limits: TcpLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// An invalid [`StreamConfig`].
pub enum StreamConfigError {
    /// The read chunk size is zero, so the stream could never make progress.
    ZeroReadSize,
}

impl fmt::Display for StreamConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroReadSize => f.write_str("stream read size must be non-zero"),
        }
    }
}

impl Error for StreamConfigError {}

#[derive(Debug)]
#[non_exhaustive]
/// Failure reading and decoding through [`TeltonikaStream`].
pub enum StreamReadError {
    /// The underlying stream reached EOF at a frame boundary.
    Closed,
    /// The underlying stream reached EOF in the middle of a frame.
    Truncated {
        /// Unconsumed bytes retained when EOF was observed.
        buffered: usize,
        /// Last exact additional-byte requirement reported by the decoder.
        needed: std::num::NonZeroUsize,
    },
    /// The decoder rejected a complete frame or encountered fatal framing.
    Decode(DecodeError),
    /// The underlying reader failed.
    Io(io::Error),
}

impl fmt::Display for StreamReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("stream closed at a frame boundary"),
            Self::Truncated { buffered, needed } => {
                write!(
                    f,
                    "stream closed with {buffered} buffered byte(s), needing {needed} more"
                )
            }
            Self::Decode(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for StreamReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Closed | Self::Truncated { .. } => None,
        }
    }
}

impl From<io::Error> for StreamReadError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Failure encoding or writing a Codec 12 command.
#[derive(Debug)]
pub enum CommandWriteError {
    /// Command input cannot be represented as a Codec 12 frame.
    Encode(EncodeError),
    /// The underlying writer failed.
    Io(io::Error),
}

impl fmt::Display for CommandWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for CommandWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<EncodeError> for CommandWriteError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

impl From<io::Error> for CommandWriteError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Pull-based framing over a synchronous or Tokio byte stream.
///
/// The wrapper owns its receive buffer and returns owned [`Frame`] values. It
/// reads only when you call a read method, never runs a background task, and
/// never acknowledges a frame automatically. One instance should exclusively
/// own the read side: bypassing it may skip bytes already buffered here.
///
/// # Buffer ownership
///
/// A read may fetch bytes belonging to later frames. [`Self::into_inner`]
/// discards those buffered bytes, and reading directly through [`Self::get_mut`]
/// can reorder the protocol stream. Finish protocol reads before extracting or
/// directly reading the underlying transport.
///
/// # Examples
///
/// ```
/// use std::io::Cursor;
/// use nom_teltonika::{
///     encoder::encode_codec12_command,
///     protocol::Frame,
///     stream::TeltonikaStream,
/// };
///
/// let bytes = encode_codec12_command(b"getinfo").unwrap();
/// let mut stream = TeltonikaStream::new(Cursor::new(bytes));
/// let Frame::Codec12(packet) = stream.read_frame().unwrap() else {
///     panic!("expected Codec 12");
/// };
/// assert_eq!(packet.message().payload_as_str(0).unwrap().unwrap(), "getinfo");
/// ```
pub struct TeltonikaStream<S> {
    inner: S,
    config: StreamConfig,
    receive: ReceiveBuffer,
}

impl<S> TeltonikaStream<S> {
    /// Wraps a transport using [`StreamConfig::default`].
    pub fn new(inner: S) -> Self {
        Self::with_config(inner, StreamConfig::default()).expect("default stream config is valid")
    }

    /// Wraps a transport using a validated configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StreamConfigError`] if `config` does not satisfy its invariants.
    pub fn with_config(inner: S, config: StreamConfig) -> Result<Self, StreamConfigError> {
        config.validate()?;
        Ok(Self {
            inner,
            config,
            receive: ReceiveBuffer::new(config.read_size),
        })
    }

    /// Returns a shared reference to the underlying transport.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
    /// Returns a mutable reference to the underlying transport.
    ///
    /// Do not read from it: this wrapper may already hold later bytes in its own
    /// buffer. Transport-level configuration and writes remain valid uses.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
    /// Extracts the underlying transport, discarding buffered unread bytes.
    pub fn into_inner(self) -> S {
        self.inner
    }
    /// Returns the active stream configuration.
    pub const fn config(&self) -> StreamConfig {
        self.config
    }

    fn decode_buffered(&mut self) -> Result<BufferedFrame, StreamReadError> {
        match decode_tcp_frame_with_limits(self.receive.readable(), self.config.limits) {
            Ok(decoded) => {
                self.receive.consume(decoded.consumed);
                #[cfg(feature = "tracing")]
                tracing::trace!(
                    consumed = decoded.consumed,
                    buffered = self.receive.len(),
                    codec_id = decoded.value.codec_id(),
                    "decoded TCP frame"
                );
                Ok(BufferedFrame::Decoded(decoded.value))
            }
            Err(DecodeError::Incomplete { needed }) => Ok(BufferedFrame::Need(needed)),
            Err(error @ DecodeError::Rejected { consumed, .. }) => {
                self.receive.consume(consumed);
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    consumed,
                    buffered = self.receive.len(),
                    "rejected delimited TCP frame"
                );
                Err(StreamReadError::Decode(error))
            }
            Err(error) => Err(StreamReadError::Decode(error)),
        }
    }
}

enum BufferedFrame {
    Decoded(Frame),
    Need(std::num::NonZeroUsize),
}

impl<S: io::Read> TeltonikaStream<S> {
    /// Reads and validates the next owned TCP frame.
    ///
    /// Reads are greedy: one call may buffer bytes from following frames, which
    /// remain available to the next call.
    ///
    /// # Errors
    ///
    /// Returns [`StreamReadError::Closed`] for EOF at a frame boundary,
    /// [`StreamReadError::Truncated`] for EOF with partial data, and
    /// [`StreamReadError::Decode`] or [`StreamReadError::Io`] for decoder and transport
    /// failures. A rejected complete frame is consumed before its error is
    /// returned; a fatal framing error remains buffered and should normally end
    /// the connection.
    pub fn read_frame(&mut self) -> Result<Frame, StreamReadError> {
        loop {
            let needed = match self.decode_buffered()? {
                BufferedFrame::Decoded(frame) => return Ok(frame),
                BufferedFrame::Need(needed) => needed,
            };

            let read = self.inner.read(self.receive.writable(needed.get()))?;
            if read == 0 {
                return if self.receive.is_empty() {
                    Err(StreamReadError::Closed)
                } else {
                    Err(StreamReadError::Truncated {
                        buffered: self.receive.len(),
                        needed,
                    })
                };
            }
            self.receive.commit_read(read);
            #[cfg(feature = "tracing")]
            tracing::trace!(read, buffered = self.receive.len(), "read TCP bytes");
        }
    }
}

impl<S: io::Write> TeltonikaStream<S> {
    /// Writes and flushes the one-byte IMEI acceptance decision.
    ///
    /// Send `true` before expecting AVL data from an accepted TCP device.
    pub fn write_imei_approval(&mut self, accepted: bool) -> io::Result<()> {
        self.write_flushed(&encode_imei_approval(accepted))
    }

    /// Writes and flushes the number of AVL records accepted by the application.
    ///
    /// The count is an application decision; decoding a packet does not imply
    /// durable acceptance.
    pub fn write_avl_ack(&mut self, accepted_records: u32) -> io::Result<()> {
        self.write_flushed(&encode_avl_ack(accepted_records))
    }

    /// Writes and flushes a zero-record AVL negative acknowledgment.
    pub fn write_avl_nack(&mut self) -> io::Result<()> {
        self.write_flushed(&encode_avl_nack())
    }

    /// Encodes, writes, and flushes one arbitrary-byte Codec 12 command.
    ///
    /// The device must have an open GPRS session for Codec 12 commands.
    pub fn write_command(&mut self, command: impl AsRef<[u8]>) -> Result<(), CommandWriteError> {
        self.write_commands([command.as_ref()])
    }

    /// Encodes, writes, and flushes a batch of arbitrary-byte Codec 12 commands.
    ///
    /// # Panics
    ///
    /// Panics if there are more than 255 commands or the encoded frame cannot
    /// fit the Codec 12 `u32` length field.
    pub fn write_commands<'a>(
        &mut self,
        commands: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), CommandWriteError> {
        let encoded = encode_codec12_commands(commands)?;
        self.write_flushed(&encoded)?;
        Ok(())
    }

    fn write_flushed(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.inner.flush()?;
        #[cfg(feature = "tracing")]
        tracing::trace!(written = bytes.len(), "wrote and flushed protocol response");
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncRead + Unpin> TeltonikaStream<S> {
    /// Asynchronously reads and validates the next owned TCP frame.
    ///
    /// This method is cancellation-safe with respect to protocol progress:
    /// bytes already read remain in the wrapper's receive buffer for the next
    /// call. It otherwise follows [`Self::read_frame`]'s error and consumption
    /// contract.
    pub async fn read_frame_async(&mut self) -> Result<Frame, StreamReadError> {
        use tokio::io::AsyncReadExt;

        loop {
            let needed = match self.decode_buffered()? {
                BufferedFrame::Decoded(frame) => return Ok(frame),
                BufferedFrame::Need(needed) => needed,
            };
            let read = self.inner.read(self.receive.writable(needed.get())).await?;
            if read == 0 {
                return if self.receive.is_empty() {
                    Err(StreamReadError::Closed)
                } else {
                    Err(StreamReadError::Truncated {
                        buffered: self.receive.len(),
                        needed,
                    })
                };
            }
            self.receive.commit_read(read);
            #[cfg(feature = "tracing")]
            tracing::trace!(
                read,
                buffered = self.receive.len(),
                "read TCP bytes asynchronously"
            );
        }
    }
}

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncWrite + Unpin> TeltonikaStream<S> {
    /// Writes and flushes an IMEI decision.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_imei_approval_async(&mut self, accepted: bool) -> io::Result<()> {
        self.write_flushed_async(&encode_imei_approval(accepted))
            .await
    }

    /// Writes and flushes an AVL acknowledgment.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_avl_ack_async(&mut self, accepted_records: u32) -> io::Result<()> {
        self.write_flushed_async(&encode_avl_ack(accepted_records))
            .await
    }

    /// Writes and flushes an AVL negative acknowledgment.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_avl_nack_async(&mut self) -> io::Result<()> {
        self.write_flushed_async(&encode_avl_nack()).await
    }

    /// Writes and flushes one Codec 12 command.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_command_async(
        &mut self,
        command: impl AsRef<[u8]>,
    ) -> Result<(), CommandWriteError> {
        self.write_commands_async([command.as_ref()]).await
    }

    /// Writes and flushes a Codec 12 command batch.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_commands_async<'a>(
        &mut self,
        commands: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), CommandWriteError> {
        let encoded = encode_codec12_commands(commands)?;
        self.write_flushed_async(&encoded).await?;
        Ok(())
    }

    async fn write_flushed_async(&mut self, bytes: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.inner.write_all(bytes).await?;
        self.inner.flush().await?;
        #[cfg(feature = "tracing")]
        tracing::trace!(
            written = bytes.len(),
            "wrote and flushed protocol response asynchronously"
        );
        Ok(())
    }
}

struct ReceiveBuffer {
    storage: Vec<u8>,
    head: usize,
    tail: usize,
    read_size: usize,
}

impl ReceiveBuffer {
    fn new(read_size: usize) -> Self {
        Self {
            storage: vec![0; read_size],
            head: 0,
            tail: 0,
            read_size,
        }
    }

    fn readable(&self) -> &[u8] {
        &self.storage[self.head..self.tail]
    }
    fn len(&self) -> usize {
        self.tail - self.head
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn writable(&mut self, needed: usize) -> &mut [u8] {
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        } else if self.head > 0
            && self.head >= self.storage.len() / 2
            && self.len() <= self.read_size
        {
            // Decoding advances `head` instead of shifting after every frame.
            // Compact only after enough prefix space is wasted and the live tail
            // is small, amortizing copies on streams containing many frames.
            self.storage.copy_within(self.head..self.tail, 0);
            self.tail = self.len();
            self.head = 0;
        }

        let read_length = needed.min(self.read_size);
        let required = self
            .tail
            .checked_add(read_length)
            .expect("receive buffer size overflow");
        if self.storage.len() < required {
            self.storage.resize(required, 0);
        }
        &mut self.storage[self.tail..required]
    }

    fn commit_read(&mut self, length: usize) {
        assert!(length <= self.read_size, "reader exceeded provided buffer");
        self.tail += length;
    }

    fn consume(&mut self, length: usize) {
        self.head += length;
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
    }
}
