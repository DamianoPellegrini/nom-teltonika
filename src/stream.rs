use std::{error::Error, fmt, io};

use crate::{
    Frame, Limits, LimitsError, ParseError, encode_avl_ack, encode_avl_nack,
    encode_codec12_commands, encode_imei_approval, parse_tcp_frame_with_limits,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    pub read_size: usize,
    pub limits: Limits,
}

impl StreamConfig {
    pub fn new(read_size: usize, limits: Limits) -> Result<Self, StreamConfigError> {
        let config = Self { read_size, limits };
        config.validate()?;
        Ok(config)
    }

    fn validate(self) -> Result<(), StreamConfigError> {
        if self.read_size == 0 {
            return Err(StreamConfigError::ZeroReadSize);
        }
        self.limits
            .validate()
            .map_err(StreamConfigError::InvalidLimits)
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            read_size: 4 * 1024,
            limits: Limits::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamConfigError {
    ZeroReadSize,
    InvalidLimits(LimitsError),
}

impl fmt::Display for StreamConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroReadSize => f.write_str("stream read size must be non-zero"),
            Self::InvalidLimits(error) => write!(f, "invalid stream limits: {error}"),
        }
    }
}

impl Error for StreamConfigError {}

#[derive(Debug)]
#[non_exhaustive]
pub enum StreamError {
    Closed,
    Truncated { buffered: usize },
    Parse(ParseError),
    Io(io::Error),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("stream closed at a frame boundary"),
            Self::Truncated { buffered } => {
                write!(f, "stream closed with {buffered} buffered byte(s)")
            }
            Self::Parse(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for StreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Closed | Self::Truncated { .. } => None,
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct TeltonikaStream<S> {
    inner: S,
    config: StreamConfig,
    receive: ReceiveBuffer,
    read_chunk: Vec<u8>,
}

impl<S> TeltonikaStream<S> {
    pub fn new(inner: S) -> Self {
        Self::with_config(inner, StreamConfig::default()).expect("default stream config is valid")
    }

    pub fn with_config(inner: S, config: StreamConfig) -> Result<Self, StreamConfigError> {
        config.validate()?;
        Ok(Self {
            inner,
            config,
            receive: ReceiveBuffer::new(config.read_size),
            read_chunk: vec![0; config.read_size],
        })
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
    pub fn into_inner(self) -> S {
        self.inner
    }
    pub const fn config(&self) -> StreamConfig {
        self.config
    }
}

impl<S: io::Read> TeltonikaStream<S> {
    pub fn read_frame(&mut self) -> Result<Frame, StreamError> {
        loop {
            match parse_tcp_frame_with_limits(self.receive.readable(), self.config.limits) {
                Ok(parsed) => {
                    self.receive.consume(parsed.consumed);
                    #[cfg(feature = "tracing")]
                    tracing::trace!(
                        consumed = parsed.consumed,
                        buffered = self.receive.len(),
                        codec_id = parsed.value.codec_id(),
                        "decoded TCP frame"
                    );
                    return Ok(parsed.value);
                }
                Err(ParseError::Incomplete { .. }) => {}
                Err(error @ ParseError::Rejected { consumed, .. }) => {
                    self.receive.consume(consumed);
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        consumed,
                        buffered = self.receive.len(),
                        "rejected delimited TCP frame"
                    );
                    return Err(StreamError::Parse(error));
                }
                Err(error) => return Err(StreamError::Parse(error)),
            }

            let read = self.inner.read(&mut self.read_chunk)?;
            if read == 0 {
                return if self.receive.is_empty() {
                    Err(StreamError::Closed)
                } else {
                    Err(StreamError::Truncated {
                        buffered: self.receive.len(),
                    })
                };
            }
            self.receive.extend(&self.read_chunk[..read]);
            #[cfg(feature = "tracing")]
            tracing::trace!(read, buffered = self.receive.len(), "read TCP bytes");
        }
    }
}

impl<S: io::Write> TeltonikaStream<S> {
    pub fn write_imei_approval(&mut self, accepted: bool) -> Result<(), StreamError> {
        self.write_flushed(&encode_imei_approval(accepted))
    }

    pub fn write_avl_ack(&mut self, accepted_records: u32) -> Result<(), StreamError> {
        self.write_flushed(&encode_avl_ack(accepted_records))
    }

    pub fn write_avl_nack(&mut self) -> Result<(), StreamError> {
        self.write_flushed(&encode_avl_nack())
    }

    pub fn write_command(&mut self, command: impl AsRef<[u8]>) -> Result<(), StreamError> {
        self.write_commands([command.as_ref()])
    }

    pub fn write_commands<'a>(
        &mut self,
        commands: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), StreamError> {
        self.write_flushed(&encode_codec12_commands(commands))
    }

    fn write_flushed(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.inner.write_all(bytes)?;
        self.inner.flush()?;
        #[cfg(feature = "tracing")]
        tracing::trace!(written = bytes.len(), "wrote and flushed protocol response");
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncRead + Unpin> TeltonikaStream<S> {
    pub async fn read_frame_async(&mut self) -> Result<Frame, StreamError> {
        use tokio::io::AsyncReadExt;

        loop {
            match parse_tcp_frame_with_limits(self.receive.readable(), self.config.limits) {
                Ok(parsed) => {
                    self.receive.consume(parsed.consumed);
                    #[cfg(feature = "tracing")]
                    tracing::trace!(
                        consumed = parsed.consumed,
                        buffered = self.receive.len(),
                        codec_id = parsed.value.codec_id(),
                        "decoded TCP frame"
                    );
                    return Ok(parsed.value);
                }
                Err(ParseError::Incomplete { .. }) => {}
                Err(error @ ParseError::Rejected { consumed, .. }) => {
                    self.receive.consume(consumed);
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        consumed,
                        buffered = self.receive.len(),
                        "rejected delimited TCP frame"
                    );
                    return Err(StreamError::Parse(error));
                }
                Err(error) => return Err(StreamError::Parse(error)),
            }
            let read = self.inner.read(&mut self.read_chunk).await?;
            if read == 0 {
                return if self.receive.is_empty() {
                    Err(StreamError::Closed)
                } else {
                    Err(StreamError::Truncated {
                        buffered: self.receive.len(),
                    })
                };
            }
            self.receive.extend(&self.read_chunk[..read]);
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
    pub async fn write_imei_approval_async(&mut self, accepted: bool) -> Result<(), StreamError> {
        self.write_flushed_async(&encode_imei_approval(accepted))
            .await
    }

    /// Writes and flushes an AVL acknowledgment.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_avl_ack_async(&mut self, accepted_records: u32) -> Result<(), StreamError> {
        self.write_flushed_async(&encode_avl_ack(accepted_records))
            .await
    }

    /// Writes and flushes an AVL negative acknowledgment.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_avl_nack_async(&mut self) -> Result<(), StreamError> {
        self.write_flushed_async(&encode_avl_nack()).await
    }

    /// Writes and flushes one Codec 12 command.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_command_async(
        &mut self,
        command: impl AsRef<[u8]>,
    ) -> Result<(), StreamError> {
        self.write_commands_async([command.as_ref()]).await
    }

    /// Writes and flushes a Codec 12 command batch.
    ///
    /// This operation is not cancellation-safe. Close the connection after a
    /// cancelled or otherwise partial write.
    pub async fn write_commands_async<'a>(
        &mut self,
        commands: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<(), StreamError> {
        self.write_flushed_async(&encode_codec12_commands(commands))
            .await
    }

    async fn write_flushed_async(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
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
    read_size: usize,
}

impl ReceiveBuffer {
    fn new(read_size: usize) -> Self {
        Self {
            storage: Vec::with_capacity(read_size),
            head: 0,
            read_size,
        }
    }

    fn readable(&self) -> &[u8] {
        &self.storage[self.head..]
    }
    fn len(&self) -> usize {
        self.storage.len() - self.head
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn extend(&mut self, bytes: &[u8]) {
        if self.head == self.storage.len() {
            self.storage.clear();
            self.head = 0;
        } else if self.head > 0
            && self.head >= self.storage.capacity() / 2
            && self.len() <= self.read_size
        {
            self.storage.copy_within(self.head.., 0);
            self.storage.truncate(self.len());
            self.head = 0;
        }
        self.storage.extend_from_slice(bytes);
    }

    fn consume(&mut self, length: usize) {
        self.head += length;
        if self.head == self.storage.len() {
            self.storage.clear();
            self.head = 0;
        }
    }
}
