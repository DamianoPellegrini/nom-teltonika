use core::{fmt, num::NonZeroUsize};
use std::io;
use std::vec::Vec;

use crate::decoder::{FrameError, HeaderError};
use crate::decoder::{IMEI_PREFIX_LEN, MAX_CODEC8_FRAME_LEN, frame_len, imei_len, validate_frame};
use crate::encoder::{
    EncodeGprsError, encode_avl_ack, encode_avl_nack, encode_gprs_frame, encode_imei_approval,
};
use crate::protocol::{FrameView, GprsMessageType, ImeiError, ImeiView};

/// Size of the read buffer, by default and at least: the longest Codec 8
/// frame.
const DEFAULT_CAPACITY: usize = MAX_CODEC8_FRAME_LEN;

/// A Teltonika TCP connection over a byte stream.
///
/// Reads the IMEI handshake and then frames, and writes the server's answers.
/// It reads only when a read method is called, never acknowledges on its own,
/// and returns views that borrow its buffer until the next call; call
/// `evaluate` on a view to keep it longer.
///
/// A read may buffer bytes of the following frames: don't read from the
/// transport directly (through [`get_mut`](Self::get_mut)) once reading
/// through this wrapper.
///
/// # Memory
///
/// The read buffer starts at its capacity, 1280 bytes by default and at
/// least: the longest Codec 8 frame ([Codec], section "Codec 8"), which also
/// holds the IMEI handshake. A server with 10,000 open connections starts
/// with about 13 MB of read buffers.
///
/// - Why whole frames: a frame must be buffered whole before it is decoded,
///   because its CRC covers all of its data and views borrow it in place.
/// - Why each read fills the buffer: every read asks the transport for all
///   the free space, as [`BufReader`](std::io::BufReader) does with its
///   capacity. When a device has sent several frames at once, a larger
///   buffer takes them in fewer reads; raise the capacity with
///   [`with_capacity`](Self::with_capacity) for that, for example to 2560
///   bytes for two AVL frames per read.
/// - Why it grows, and how far: Teltonika documents no length limit for
///   Codec 16 packets or Codec 12 messages ([Data Sending Protocols],
///   section "Codec 12"), so a frame longer than the buffer makes it grow,
///   up to the 65,535 bytes the decoder accepts; a header declaring more is
///   refused before any of its bytes are waited for. That bounds what one
///   connection can hold, whatever its peer sends.
/// - Why it grows once: the buffer grows only when it is full of a frame it
///   can't hold, and then in one step to the frame's length, rounded up to a
///   power of two. So a long frame costs one allocation, and a peer must
///   send a buffer's worth of a frame, not just declare it, to cause it.
/// - Why it never shrinks on its own: a device that sends long frames sends
///   them again, and shrinking after each would allocate twice per frame.
///   The buffer keeps its size until the stream is dropped or
///   [`shrink_to_fit`](Self::shrink_to_fit) is called, which is the
///   caller's choice: for example for connections that stay open but idle.
/// - Why it is linear: bytes are appended at the tail and consumed from the
///   head by moving an index, so the unread bytes are always one slice,
///   which views borrow. When the frame at the head can't be completed in
///   place, the unread bytes are moved to the front, which copies only
///   them, and the buffer grows only if it is then full. This is the linear
///   buffer of the [`circular`] crate and of [`BytesMut::reserve`]; a ring
///   buffer would avoid the move, but a frame wrapping past its end would
///   have to be copied anyway to be borrowed as one slice.
///
/// # Examples
///
/// ```
/// use std::io::Cursor;
///
/// use nom_teltonika::encoder::encode_gprs_frame;
/// use nom_teltonika::protocol::{FrameView, GprsMessageType};
/// use nom_teltonika::tcp::TeltonikaTcpStream;
///
/// let mut bytes = b"\x00\x0f356307042441013".to_vec();
/// bytes.extend(encode_gprs_frame(GprsMessageType::Command, &["getinfo"])?);
/// let mut stream = TeltonikaTcpStream::new(Cursor::new(bytes));
///
/// assert_eq!(stream.read_imei()?.as_str(), "356307042441013");
/// let FrameView::Gprs(packet) = stream.read_frame()? else {
///     panic!("expected a GPRS frame");
/// };
/// assert_eq!(packet.messages().next().unwrap().payload(), b"getinfo");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [Codec]: https://wiki.teltonika-gps.com/view/Codec
/// [`circular`]: https://docs.rs/circular/latest/circular/struct.Buffer.html
/// [`BytesMut::reserve`]: https://docs.rs/bytes/latest/bytes/struct.BytesMut.html#method.reserve
/// [Data Sending Protocols]: https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols
#[derive(Debug)]
pub struct TeltonikaTcpStream<S> {
    inner: S,
    /// The read buffer. Every byte is initialized: its length is the
    /// buffer's current size.
    // TODO: Keep the bytes after the tail uninitialized, to skip zeroing a
    // new or grown buffer, once `Read::read_buf` and `BorrowedBuf` are stable
    // (https://github.com/rust-lang/rust/issues/78485). Tokio's `ReadBuf`
    // already accepts uninitialized memory, but using it here would take an
    // `unsafe` block beyond the one the crate allows.
    storage: Vec<u8>,
    /// Start of the unread bytes in `storage`.
    head: usize,
    /// End of the unread bytes in `storage`.
    tail: usize,
    /// Size the buffer starts at, and returns to in `shrink_to_fit`.
    min_capacity: usize,
}

/// How a stream ended while a read method waited for bytes.
enum Eof {
    /// Between two units: nothing of the next one was buffered.
    Clean,
    /// Inside a unit, with `buffered` bytes of it read and `needed` missing.
    MidUnit {
        buffered: usize,
        needed: NonZeroUsize,
    },
}

// `S` is unbounded and each capability comes from its own impl block, as for
// `std::io::BufReader`: a read-only or write-only transport (a replay file in
// tests, one half of a split socket) gets exactly the methods it supports,
// and generic callers don't repeat bounds they don't use. Sealing `S` to
// `Read + Write` and their Tokio versions would rule those transports out and
// buy nothing: a stream over a type with neither has only the accessors.
impl<S> TeltonikaTcpStream<S> {
    /// Creates a stream over `inner` with a 1280-byte read buffer.
    ///
    /// See [Memory] for how the buffer grows for longer frames.
    ///
    /// [Memory]: Self#memory
    pub fn new(inner: S) -> Self {
        Self::with_capacity(DEFAULT_CAPACITY, inner)
    }

    /// Creates a stream over `inner` with a read buffer of at least
    /// `capacity` bytes.
    ///
    /// Follows [`BufWriter::with_capacity`](std::io::BufWriter::with_capacity).
    /// Every read asks for all the free space, so a larger buffer means fewer
    /// reads when frames arrive together (see [Memory]). A capacity under
    /// 1280 bytes, the longest AVL frame, is raised to it, as
    /// [`Vec::with_capacity`] may allocate more than asked: a smaller buffer
    /// would have to grow for the first long AVL frame.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use nom_teltonika::tcp::TeltonikaTcpStream;
    ///
    /// // Room for two AVL frames per read.
    /// let stream = TeltonikaTcpStream::with_capacity(2560, Cursor::new(b""));
    /// assert_eq!(stream.capacity(), 2560);
    ///
    /// let stream = TeltonikaTcpStream::with_capacity(512, Cursor::new(b""));
    /// assert_eq!(stream.capacity(), 1280);
    /// ```
    ///
    /// [Memory]: Self#memory
    pub fn with_capacity(capacity: usize, inner: S) -> Self {
        let capacity = capacity.max(DEFAULT_CAPACITY);
        Self {
            inner,
            storage: std::vec![0; capacity],
            head: 0,
            tail: 0,
            min_capacity: capacity,
        }
    }

    /// Returns the current size of the read buffer: its capacity, or more
    /// once it has held a longer frame (see [Memory]).
    ///
    /// [Memory]: Self#memory
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Returns a shared reference to the transport.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the transport.
    ///
    /// It is inadvisable to read from the transport directly, as for
    /// [`BufWriter::get_mut`](std::io::BufWriter::get_mut): this wrapper may
    /// already have buffered its next bytes (see [`buffer`](Self::buffer)),
    /// so a direct read skips them and the next frame is read from the wrong
    /// offset. Writing is safe, since this wrapper doesn't buffer writes.
    ///
    /// It exists for operations that need `&mut` but don't read. For
    /// example, devices can send their records over TLS ([FMB120 GPRS
    /// settings], section "Server Settings"), and closing a TLS transport
    /// cleanly sends a `close_notify` alert, which takes `&mut`.
    ///
    /// [FMB120 GPRS settings]: https://wiki.teltonika-gps.com/view/FMB120_GPRS_settings
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Returns the bytes read from the transport but not yet decoded.
    ///
    /// They belong to the next handshake or frame; see
    /// [`BufReader::buffer`](std::io::BufReader::buffer).
    pub fn buffer(&self) -> &[u8] {
        &self.storage[self.head..self.tail]
    }

    /// Returns the transport, dropping the buffered bytes.
    ///
    /// Use [`into_parts`](Self::into_parts) to keep them.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Returns the transport and the bytes read from it but not yet
    /// decoded.
    ///
    /// Reuses the read buffer's allocation. Follows
    /// [`BufWriter::into_parts`](std::io::BufWriter::into_parts), which
    /// returns its unwritten bytes the same way.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        let mut unread = self.storage;
        unread.copy_within(self.head..self.tail, 0);
        unread.truncate(self.tail - self.head);
        (self.inner, unread)
    }

    /// Shrinks the read buffer back to the capacity it was created with, or
    /// to the unread bytes if they are longer.
    ///
    /// The buffer never shrinks on its own (see [Memory]): call this to give
    /// back the memory a long frame took, for example on a connection that
    /// stays open but idle. Follows [`Vec::shrink_to_fit`].
    ///
    /// [Memory]: Self#memory
    pub fn shrink_to_fit(&mut self) {
        self.storage.copy_within(self.head..self.tail, 0);
        self.tail -= self.head;
        self.head = 0;
        self.storage.truncate(self.tail.max(self.min_capacity));
        self.storage.shrink_to_fit();
    }

    /// Makes room after the unread bytes to read more of the unit at the
    /// head, which misses `needed` bytes. A read then takes all the free
    /// space, `storage[tail..]`.
    ///
    /// The free space may be less than `needed`: the buffer grows only once
    /// it is full, so that a peer must send a buffer's worth of a unit to
    /// make it grow, and then in one step to the unit's length.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::OutOfMemory`] if the buffer can't grow.
    fn make_room(&mut self, needed: NonZeroUsize) -> io::Result<()> {
        if self.storage.len() - self.tail >= needed.get() && self.head != self.tail {
            return Ok(());
        }
        // Move the unread bytes to the front: all the free space follows.
        self.storage.copy_within(self.head..self.tail, 0);
        self.tail -= self.head;
        self.head = 0;
        if self.tail == self.storage.len() {
            let len = (self.tail + needed.get()).next_power_of_two();
            self.storage
                .try_reserve_exact(len - self.tail)
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            self.storage.resize(len, 0);
        }
        Ok(())
    }

    /// Consumes the first `len` unread bytes and returns them.
    ///
    /// # Panics
    ///
    /// Panics if fewer than `len` bytes are unread.
    fn consume(&mut self, len: usize) -> &[u8] {
        let start = self.head;
        assert!(
            start + len <= self.tail,
            "consumed more bytes than are unread"
        );
        self.head += len;
        &self.storage[start..self.head]
    }

    /// Returns the number of bytes missing from a unit of `len` bytes at the
    /// head of the unread bytes, or `None` once it is buffered whole.
    ///
    /// `len` comes from [`imei_len`] or [`frame_len`], which return the
    /// length of what must be buffered next until the unit's own length is
    /// known: a read method loops on this value until nothing is missing.
    fn missing(&self, len: usize) -> Option<NonZeroUsize> {
        NonZeroUsize::new(len.saturating_sub(self.tail - self.head))
    }

    /// Consumes the buffered handshake of `len` bytes and checks its text.
    fn finish_imei(&mut self, len: usize) -> Result<ImeiView<'_>, ReadImeiError> {
        let result = ImeiView::try_from(&self.consume(len)[IMEI_PREFIX_LEN..]);
        #[cfg(feature = "tracing")]
        match &result {
            Ok(_) => tracing::trace!(consumed = len, "read IMEI handshake"),
            Err(error) => tracing::debug!(%error, "invalid IMEI handshake"),
        }
        result.map_err(ReadImeiError::NotAscii)
    }

    /// Returns the length of the frame at the head of the unread bytes, as
    /// [`frame_len`] does.
    fn next_frame_len(&self) -> Result<usize, ReadFrameError> {
        frame_len(self.buffer()).map_err(|error| {
            #[cfg(feature = "tracing")]
            tracing::debug!(%error, "invalid TCP frame header");
            ReadFrameError::InvalidHeader(error)
        })
    }

    /// Consumes the buffered frame of `len` bytes and decodes it.
    fn finish_frame(&mut self, len: usize) -> Result<FrameView<'_>, ReadFrameError> {
        let result = validate_frame(self.consume(len));
        #[cfg(feature = "tracing")]
        match &result {
            Ok(frame) => tracing::trace!(
                codec_id = u8::from(frame.codec()),
                consumed = len,
                "read TCP frame"
            ),
            Err(error) => tracing::debug!(%error, consumed = len, "skipped invalid TCP frame"),
        }
        result.map_err(ReadFrameError::InvalidFrame)
    }

    /// Returns how the stream ended, with `needed` bytes missing from the
    /// unit at the head: between two units or inside one.
    fn eof(&self, needed: NonZeroUsize) -> Eof {
        match self.tail - self.head {
            0 => Eof::Clean,
            buffered => Eof::MidUnit { buffered, needed },
        }
    }
}

impl<S: io::Read> TeltonikaTcpStream<S> {
    /// Reads once from the transport, with room for at least `needed` more
    /// bytes, and returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns the transport's error, or [`io::ErrorKind::OutOfMemory`] if
    /// the buffer can't grow.
    fn fill(&mut self, needed: NonZeroUsize) -> io::Result<usize> {
        self.make_room(needed)?;
        let read = self.inner.read(&mut self.storage[self.tail..])?;
        self.tail += read;
        Ok(read)
    }

    /// Reads the IMEI handshake that opens a TCP session.
    ///
    /// Reads until the handshake is buffered, then decodes it as
    /// [`take_imei`](crate::decoder::take_imei) does. The result borrows this stream until the next
    /// call.
    ///
    /// # Errors
    ///
    /// Returns [`ReadImeiError`]. After `NotAscii` the handshake is consumed;
    /// after the other errors, close the connection.
    pub fn read_imei(&mut self) -> Result<ImeiView<'_>, ReadImeiError> {
        loop {
            let len = imei_len(self.buffer());
            let Some(needed) = self.missing(len) else {
                return self.finish_imei(len);
            };
            if self.fill(needed)? == 0 {
                return Err(self.eof(needed).into());
            }
        }
    }

    /// Reads the next TCP frame.
    ///
    /// Reads until a whole frame is buffered, then decodes it as
    /// [`take_frame`](crate::decoder::take_frame) does. A read may buffer the following frames too;
    /// they are returned by the next calls. The result borrows this stream
    /// until the next call.
    ///
    /// # Errors
    ///
    /// Returns [`ReadFrameError`]. After `InvalidFrame` the frame is
    /// consumed and the next one can be read; after the other errors, close
    /// the connection. If the buffer can't grow for a long frame, returns
    /// `Io` with [`io::ErrorKind::OutOfMemory`].
    pub fn read_frame(&mut self) -> Result<FrameView<'_>, ReadFrameError> {
        loop {
            let len = self.next_frame_len()?;
            let Some(needed) = self.missing(len) else {
                return self.finish_frame(len);
            };
            if self.fill(needed)? == 0 {
                return Err(self.eof(needed).into());
            }
        }
    }
}

impl<S: io::Write> TeltonikaTcpStream<S> {
    /// Writes and flushes the answer to the IMEI handshake.
    ///
    /// # Errors
    ///
    /// Returns the transport's error.
    pub fn write_imei_approval(&mut self, accepted: bool) -> io::Result<()> {
        self.write_flushed(&encode_imei_approval(accepted))
    }

    /// Writes and flushes the acknowledgment of an AVL packet.
    ///
    /// Pass the number of records your application has accepted.
    ///
    /// # Errors
    ///
    /// Returns the transport's error.
    pub fn write_avl_ack(&mut self, accepted_records: u32) -> io::Result<()> {
        self.write_flushed(&encode_avl_ack(accepted_records))
    }

    /// Writes and flushes the negative acknowledgment of an AVL packet.
    ///
    /// # Errors
    ///
    /// Returns the transport's error.
    pub fn write_avl_nack(&mut self) -> io::Result<()> {
        self.write_flushed(&encode_avl_nack())
    }

    /// Encodes, writes, and flushes one Codec 12 command.
    ///
    /// The device accepts commands once its AVL data is acknowledged, while
    /// the session stays open.
    ///
    /// # Errors
    ///
    /// Returns [`WriteCommandError`].
    pub fn write_command(&mut self, command: impl AsRef<[u8]>) -> Result<(), WriteCommandError> {
        self.write_commands(&[command])
    }

    /// Encodes, writes, and flushes Codec 12 commands in one frame.
    ///
    /// # Errors
    ///
    /// Returns [`WriteCommandError`].
    pub fn write_commands<C: AsRef<[u8]>>(
        &mut self,
        commands: &[C],
    ) -> Result<(), WriteCommandError> {
        let frame = encode_gprs_frame(GprsMessageType::Command, commands)?;
        self.write_flushed(&frame)?;
        Ok(())
    }

    fn write_flushed(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.inner.flush()?;
        #[cfg(feature = "tracing")]
        tracing::trace!(written = bytes.len(), "wrote TCP response");
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncRead + Unpin> TeltonikaTcpStream<S> {
    /// Reads once from the transport, with room for at least `needed` more
    /// bytes, and returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns the transport's error, or [`io::ErrorKind::OutOfMemory`] if
    /// the buffer can't grow.
    async fn fill_async(&mut self, needed: NonZeroUsize) -> io::Result<usize> {
        use tokio::io::AsyncReadExt;

        self.make_room(needed)?;
        let read = self.inner.read(&mut self.storage[self.tail..]).await?;
        self.tail += read;
        Ok(read)
    }

    /// Reads the IMEI handshake that opens a TCP session.
    ///
    /// Same as [`read_imei`](Self::read_imei). Cancel-safe: bytes already
    /// read stay buffered for the next call.
    ///
    /// # Errors
    ///
    /// Returns [`ReadImeiError`], as [`read_imei`](Self::read_imei) does.
    pub async fn read_imei_async(&mut self) -> Result<ImeiView<'_>, ReadImeiError> {
        loop {
            let len = imei_len(self.buffer());
            let Some(needed) = self.missing(len) else {
                return self.finish_imei(len);
            };
            if self.fill_async(needed).await? == 0 {
                return Err(self.eof(needed).into());
            }
        }
    }

    /// Reads the next TCP frame.
    ///
    /// Same as [`read_frame`](Self::read_frame). Cancel-safe: bytes already
    /// read stay buffered for the next call.
    ///
    /// # Errors
    ///
    /// Returns [`ReadFrameError`], as [`read_frame`](Self::read_frame) does.
    pub async fn read_frame_async(&mut self) -> Result<FrameView<'_>, ReadFrameError> {
        loop {
            let len = self.next_frame_len()?;
            let Some(needed) = self.missing(len) else {
                return self.finish_frame(len);
            };
            if self.fill_async(needed).await? == 0 {
                return Err(self.eof(needed).into());
            }
        }
    }
}

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncWrite + Unpin> TeltonikaTcpStream<S> {
    /// Writes and flushes the answer to the IMEI handshake.
    ///
    /// Not cancel-safe: after a cancelled write, close the connection.
    ///
    /// # Errors
    ///
    /// Returns the transport's error.
    pub async fn write_imei_approval_async(&mut self, accepted: bool) -> io::Result<()> {
        self.write_flushed_async(&encode_imei_approval(accepted))
            .await
    }

    /// Writes and flushes the acknowledgment of an AVL packet.
    ///
    /// Not cancel-safe: after a cancelled write, close the connection.
    ///
    /// # Errors
    ///
    /// Returns the transport's error.
    pub async fn write_avl_ack_async(&mut self, accepted_records: u32) -> io::Result<()> {
        self.write_flushed_async(&encode_avl_ack(accepted_records))
            .await
    }

    /// Writes and flushes the negative acknowledgment of an AVL packet.
    ///
    /// Not cancel-safe: after a cancelled write, close the connection.
    ///
    /// # Errors
    ///
    /// Returns the transport's error.
    pub async fn write_avl_nack_async(&mut self) -> io::Result<()> {
        self.write_flushed_async(&encode_avl_nack()).await
    }

    /// Encodes, writes, and flushes one Codec 12 command.
    ///
    /// Not cancel-safe: after a cancelled write, close the connection.
    ///
    /// # Errors
    ///
    /// Returns [`WriteCommandError`].
    pub async fn write_command_async(
        &mut self,
        command: impl AsRef<[u8]>,
    ) -> Result<(), WriteCommandError> {
        self.write_commands_async(&[command]).await
    }

    /// Encodes, writes, and flushes Codec 12 commands in one frame.
    ///
    /// Not cancel-safe: after a cancelled write, close the connection.
    ///
    /// # Errors
    ///
    /// Returns [`WriteCommandError`].
    pub async fn write_commands_async<C: AsRef<[u8]>>(
        &mut self,
        commands: &[C],
    ) -> Result<(), WriteCommandError> {
        let frame = encode_gprs_frame(GprsMessageType::Command, commands)?;
        self.write_flushed_async(&frame).await?;
        Ok(())
    }

    async fn write_flushed_async(&mut self, bytes: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        self.inner.write_all(bytes).await?;
        self.inner.flush().await?;
        #[cfg(feature = "tracing")]
        tracing::trace!(written = bytes.len(), "wrote TCP response");
        Ok(())
    }
}

/// The error returned by [`TeltonikaTcpStream::read_imei`].
#[derive(Debug)]
pub enum ReadImeiError {
    /// The connection closed before any byte of the handshake.
    Closed,
    /// The connection closed in the middle of the handshake.
    Truncated {
        /// Bytes of the handshake received.
        buffered: usize,
        /// Bytes still missing.
        needed: NonZeroUsize,
    },
    /// The handshake text is not ASCII. The handshake is consumed.
    NotAscii(ImeiError),
    /// The transport failed.
    Io(io::Error),
}

/// The error returned by [`TeltonikaTcpStream::read_frame`].
#[derive(Debug)]
pub enum ReadFrameError {
    /// The connection closed between two frames.
    Closed,
    /// The connection closed in the middle of a frame.
    Truncated {
        /// Bytes of the frame received.
        buffered: usize,
        /// Bytes still missing.
        needed: NonZeroUsize,
    },
    /// The frame is invalid and consumed: the next one can be read. The
    /// device expects a negative acknowledgment for AVL data.
    InvalidFrame(FrameError),
    /// The frame header can't delimit a frame, so the next frame can't be
    /// found. Close the connection.
    InvalidHeader(HeaderError),
    /// The transport failed.
    Io(io::Error),
}

/// The error returned when writing Codec 12 commands.
#[derive(Debug)]
pub enum WriteCommandError {
    /// The commands can't form a frame.
    Encode(EncodeGprsError),
    /// The transport failed.
    Io(io::Error),
}

impl From<Eof> for ReadImeiError {
    fn from(eof: Eof) -> Self {
        match eof {
            Eof::Clean => Self::Closed,
            Eof::MidUnit { buffered, needed } => Self::Truncated { buffered, needed },
        }
    }
}

impl From<Eof> for ReadFrameError {
    fn from(eof: Eof) -> Self {
        match eof {
            Eof::Clean => Self::Closed,
            Eof::MidUnit { buffered, needed } => Self::Truncated { buffered, needed },
        }
    }
}

impl From<io::Error> for ReadImeiError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<io::Error> for ReadFrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<io::Error> for WriteCommandError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<EncodeGprsError> for WriteCommandError {
    fn from(error: EncodeGprsError) -> Self {
        Self::Encode(error)
    }
}

impl fmt::Display for ReadImeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("connection closed before the IMEI handshake"),
            Self::Truncated { buffered, needed } => write!(
                f,
                "connection closed in the IMEI handshake after {buffered} byte(s), {needed} missing"
            ),
            Self::NotAscii(_) => f.write_str("IMEI is not ASCII"),
            Self::Io(_) => f.write_str("failed to read the IMEI handshake"),
        }
    }
}

impl fmt::Display for ReadFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("connection closed"),
            Self::Truncated { buffered, needed } => write!(
                f,
                "connection closed in a frame after {buffered} byte(s), {needed} missing"
            ),
            Self::InvalidFrame(_) => f.write_str("invalid TCP frame"),
            Self::InvalidHeader(_) => f.write_str("invalid TCP frame header"),
            Self::Io(_) => f.write_str("failed to read a TCP frame"),
        }
    }
}

impl fmt::Display for WriteCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(_) => f.write_str("failed to encode Codec 12 commands"),
            Self::Io(_) => f.write_str("failed to write Codec 12 commands"),
        }
    }
}

impl core::error::Error for ReadImeiError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NotAscii(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Closed | Self::Truncated { .. } => None,
        }
    }
}

impl core::error::Error for ReadFrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidFrame(error) => Some(error),
            Self::InvalidHeader(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Closed | Self::Truncated { .. } => None,
        }
    }
}

impl core::error::Error for WriteCommandError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream with a `capacity`-byte buffer, under the public minimum, so
    /// that the buffer logic is tested on a few bytes.
    fn stream(capacity: usize) -> TeltonikaTcpStream<()> {
        TeltonikaTcpStream {
            inner: (),
            storage: std::vec![0; capacity],
            head: 0,
            tail: 0,
            min_capacity: capacity,
        }
    }

    /// Makes room for `needed` bytes, then appends `bytes` as a read would,
    /// and returns the free space the read was offered.
    fn fill(stream: &mut TeltonikaTcpStream<()>, needed: usize, bytes: &[u8]) -> usize {
        stream
            .make_room(NonZeroUsize::new(needed).unwrap())
            .unwrap();
        let free = stream.storage.len() - stream.tail;
        stream.storage[stream.tail..][..bytes.len()].copy_from_slice(bytes);
        stream.tail += bytes.len();
        free
    }

    #[test]
    fn offers_all_the_free_space_to_each_read() {
        let mut stream = stream(8);
        assert_eq!(fill(&mut stream, 1, &[0; 3]), 8);
        assert_eq!(fill(&mut stream, 1, &[]), 5);
    }

    #[test]
    fn shifts_unread_bytes_to_the_front_when_a_unit_cant_finish_in_place() {
        let mut stream = stream(4);
        let ptr = stream.storage.as_ptr();
        fill(&mut stream, 1, &[1, 2, 3, 4]);
        assert_eq!(stream.consume(3), &[1, 2, 3]);

        // One unread byte at the end, two more needed: it moves to the front.
        assert_eq!(fill(&mut stream, 2, &[]), 3);
        assert_eq!(stream.buffer(), &[4]);
        assert_eq!((stream.head, stream.tail), (0, 1));
        assert!(core::ptr::eq(stream.storage.as_ptr(), ptr));
    }

    #[test]
    fn restarts_at_the_front_once_everything_is_consumed() {
        let mut stream = stream(4);
        fill(&mut stream, 1, &[1, 2]);
        stream.consume(2);

        fill(&mut stream, 1, &[3]);
        assert_eq!((stream.head, stream.tail), (0, 1));
    }

    #[test]
    fn grows_once_full_in_one_step_to_the_unit_rounded_up() {
        let mut stream = stream(4);
        let ptr_len = stream.capacity();
        // The unit needs 10 bytes: the 4 free ones are offered first.
        assert_eq!(fill(&mut stream, 10, &[0; 4]), 4);
        assert_eq!(stream.capacity(), ptr_len);

        // Full, 6 more needed, 10 in all: 16, the next power of two.
        assert_eq!(fill(&mut stream, 6, &[0; 6]), 12);
        assert_eq!(stream.capacity(), 16);
    }

    #[test]
    fn moves_the_unread_bytes_to_the_front_before_growing() {
        let mut stream = stream(4);
        fill(&mut stream, 1, &[1, 2, 3, 4]);
        stream.consume(2);

        // Two unread bytes, five more needed: moved first, with two bytes
        // free, and no growth until those are filled.
        assert_eq!(fill(&mut stream, 5, &[5, 6]), 2);
        assert_eq!(stream.capacity(), 4);
        assert_eq!(fill(&mut stream, 3, &[]), 4);
        assert_eq!(stream.capacity(), 8);
        assert_eq!(stream.buffer(), &[3, 4, 5, 6]);
        assert_eq!((stream.head, stream.tail), (0, 4));
    }

    #[test]
    fn keeps_its_size_until_asked_to_shrink() {
        let mut stream = stream(4);
        fill(&mut stream, 6, &[0; 4]);
        fill(&mut stream, 2, &[1, 2]);
        assert_eq!(stream.capacity(), 8);
        stream.consume(4);

        // The two free bytes are enough: nothing moves, nothing shrinks.
        assert_eq!(fill(&mut stream, 1, &[]), 2);
        assert_eq!(stream.capacity(), 8);

        stream.shrink_to_fit();
        assert_eq!(stream.capacity(), 4);
        assert_eq!(stream.buffer(), &[1, 2]);
    }

    #[test]
    fn shrinks_no_further_than_the_unread_bytes() {
        let mut stream = stream(2);
        fill(&mut stream, 6, &[0; 2]);
        fill(&mut stream, 4, &[0; 4]);
        stream.shrink_to_fit();
        assert_eq!(stream.capacity(), 6);
    }

    #[test]
    fn hands_back_only_the_unread_bytes() {
        let mut stream = stream(4);
        fill(&mut stream, 1, &[1, 2, 3, 4]);
        stream.consume(1);
        assert_eq!(stream.into_parts().1, [2, 3, 4]);
    }
}
