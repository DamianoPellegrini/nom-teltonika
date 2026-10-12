# Decoder TODO

## Open

- **Stream behaviour on errors.** The decoders only report errors and never
  close or answer. Decide whether the stream should do more than that.
- **Stream and UDP review.** Compare both against the Teltonika wiki and
  other parsers.
- **Encoder integration.** The encoder stands apart from the rest of the
  crate: it has its own input types (`AvlRecordFields`,
  `DatagramHeaderFields`) instead of the views and owned types the decoders
  return, so a decoded packet can't be encoded back without rebuilding it
  field by field. Decide how to join the two; one idea is a trait
  implemented on the owned types.
- **`AvlRecordFields` IO slices.** Five slices and five `with_io_*` methods,
  one per value width. A single `&[(IoId, IoValueView)]` would be what
  `record.io_elements()` yields, and would remove `ids_len` and the four
  near-identical loops of `put_record`; the encoder would then group the
  elements by width itself. Encoder only: decoding is not affected.
- **Private read buffer type.** The buffer logic of `TeltonikaTcpStream`
  (`make_room`, `consume`, `shrink_to_fit`, `into_parts`) is tested through
  a `TeltonikaTcpStream<()>` built by hand, which suggests a private buffer
  struct inside the stream. It would stay part of the stream, as decided
  under "Stream buffer": only the fields and their tests would move.
- **Codec 12, Quantity 1.** The wiki says it "is ignored when parsing the
  message", but it still gives the number of messages to read here. A frame
  whose Quantity 1 disagrees with the messages it holds is rejected. The
  alternative is to read messages until one byte of the data field is left.
- **One-pass owned decoder.** Only if storing every record proves slow.
  Measure first.

## Done

### Parsing logic

- A frame is read in three steps: the header gives its length, the frame is
  split off by that length, then the CRC and the content are checked.
- `frame_len` and `imei_len` return the length of what must be buffered
  next until the unit's own length is known, so `Incomplete` is built in one
  place and the stream needs no state of its own between reads.
- Errors are returned to the caller, who decides whether to close the
  connection.
- Size limits are checked from the header, before waiting for the bytes:
  1280 bytes for Codec 8 and Codec 8 Extended, 65,535 for every other frame.
  The IMEI has no limit.

### CRC

- Uses tables built at compile time (4 KiB) and reads 8 bytes per step. It
  was about 95% of the TCP decode time and is now about 4 times faster.
- Computing the CRC field by field while parsing was measured: about 3
  times slower than one call over the data field. They stay separate.

### Parsing code and API

- Bytes are read with `from_be_bytes`; nothing is reinterpreted as a struct.
- Only view and owned types exist. The old `take` and `put` helpers are
  gone.
- Decoders come in two styles: `take_*` moves a cursor, `parse_*` returns the
  remaining bytes. A datagram has only `take_datagram`, because nothing
  remains after it.
- Decoders return views. Owned values come from `evaluate`, with the `alloc`
  feature.
- Validation happens once, when decoding; reading a view cannot fail.
- Reading a view walks the records again to find where each one ends (about
  135 ns of 690 ns for 10 Codec 8 records). A view stores no offsets, so
  this can't be avoided.
- Views serialize directly, JSON included, without building an owned packet.

### Names

- No transport prefixes: `take_frame`, `take_datagram`, `DatagramView`. The
  I/O modules are `tcp` and `udp`.
- The two AVL readers for IDs and counts are one function, `take_uint`.
- Files are named after the unit, not the transport: `decoder/frame.rs`,
  `decoder/datagram.rs`, `protocol/datagram.rs`.
- GPRS names are one family: `encoder/gprs.rs`, `encode_gprs_frame(_into)`,
  `GprsMessageType`, read with `GprsMessageView::kind`.
- `MAX_CODEC8_FRAME_LEN` is the 1280-byte limit; `AvlCodec::max_frame_len`
  picks the limit for the decoder and the encoder.
- `crc16` is exported from the crate root, as in 0.1.

### Stream buffer

- The buffer is part of `TeltonikaTcpStream`. `BufReader` can't replace it:
  it doesn't read more while bytes are buffered, and it can't grow.
- Goal: as few reads, allocations, and shrinks as possible.
- It grows only when it is full, once, to the frame's length rounded up to a
  power of two. A peer must send a buffer's worth of a frame to make it
  grow.
- It never shrinks on its own; `shrink_to_fit` does it on request.
- Measured: growing costs about 85 ns, once, on the first long frame.

### UDP

- Any error stops decoding and is returned. An invalid datagram that has a
  header comes with its IDs and its peer address, so it can be answered.

### Counts sent twice

- AVL: the two record counts must match, as the wiki requires. Otherwise
  the packet is rejected with `RecordCountMismatch`.
- Codec 12: Quantity 2 must be present but is not compared with Quantity 1.
  The wiki says it "will not be parsed" and only recommends that it match.

### Encoder

- The AVL encoder uses the decoder's limits: 1280 bytes for Codec 8 and
  Codec 8 Extended, 65,535 for Codec 16.
- GPRS frames have two encoders, `encode_gprs_frame` and
  `encode_gprs_frame_into`, which take the message type; the stream's
  `write_command(s)` use them.
- Both encoders write the frame around the data field with one function,
  and share the decoder's length constants.
