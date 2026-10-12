use nom_teltonika::encoder::encode_gprs_frame;
use nom_teltonika::protocol::{AvlCodec, GprsMessageType};
use teltonika_simulator::Traffic;

/// Vehicles whose packets are interleaved in a corpus.
const DEVICES: usize = 256;

/// Time of every vehicle's first record, in milliseconds since the Unix
/// epoch.
const START_MILLIS: u64 = 1_700_000_000_000;

/// Milliseconds between two records of a vehicle.
const RECORD_PERIOD_MILLIS: u64 = 1_000;

const CODECS: [AvlCodec; 3] = [
    AvlCodec::Codec8,
    AvlCodec::Codec8Extended,
    AvlCodec::Codec16,
];

/// An answer to `getinfo`, in the words of the Teltonika wiki page "FMB
/// getinfo".
const RESPONSE: &str = "RTC:2023/11/14 22:13 Init:2023/11/14 5:22 UpTime:60663s PWR:SoftReset \
    RST:0 GPS:3 SAT:9 TTFF:21 TTLF:0 NOGPS: 0:0 SR:1234 FG:0 FL:0 SMS:0 REC:0 MD:1 DB:0";

/// Consecutive TCP frames to decode.
///
/// The frames are the packets of 256 simulated vehicles, taken in turn. A
/// corpus of a given length always has the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corpus {
    /// A short name, for benchmark IDs.
    pub name: &'static str,
    /// What the frames are, for the report.
    pub description: &'static str,
    /// Whether every frame is Codec 8 with at most 4 records.
    ///
    /// Every parser decodes such frames.
    pub codec8_only: bool,
    /// The frames.
    pub bytes: Vec<u8>,
    /// Number of frames.
    pub frames: u64,
    /// Number of AVL records in the frames.
    pub records: u64,
}

impl Corpus {
    /// Returns at least `len` bytes of Codec 8 frames of 1 to 4 records.
    ///
    /// `teltonika-avl-protocol` holds at most 4 records per packet and 16 IO
    /// elements of each width. The simulated records have at most 11.
    pub fn codec8(len: usize) -> Self {
        Self::build(
            "codec8",
            "Codec 8 frames of 1 to 4 records",
            true,
            len,
            |device| (AvlCodec::Codec8, 1 + device % 4),
        )
    }

    /// Returns at least `len` bytes of frames of every codec.
    ///
    /// Codec 8, 8 Extended, and 16 frames have 1 to 32 records, or as many
    /// as fit in a frame. One frame in 64 is a Codec 12 response.
    pub fn mixed(len: usize) -> Self {
        Self::build(
            "mixed",
            "Codec 8, 8 Extended, and 16 frames of 1 to 32 records, with Codec 12 responses",
            false,
            len,
            |device| {
                (
                    CODECS[device % CODECS.len()],
                    1 + device / CODECS.len() % 32,
                )
            },
        )
    }

    /// Appends the packets of [`DEVICES`] vehicles in turn, up to `len`
    /// bytes.
    ///
    /// `device` returns the codec and the records per packet of a vehicle.
    fn build(
        name: &'static str,
        description: &'static str,
        codec8_only: bool,
        len: usize,
        device: impl Fn(usize) -> (AvlCodec, usize),
    ) -> Self {
        let mut devices: Vec<_> = (0..DEVICES)
            .map(|index| {
                let (codec, records) = device(index);
                let records = u8::try_from(records).expect("at most 255 records per packet");
                Traffic::new(
                    codec,
                    records,
                    RECORD_PERIOD_MILLIS,
                    index as u64,
                    START_MILLIS,
                )
            })
            .collect();
        let response = encode_gprs_frame(GprsMessageType::Response, &[RESPONSE])
            .expect("the response fits in a frame");

        let mut corpus = Self {
            name,
            description,
            codec8_only,
            bytes: Vec::with_capacity(len + 64 * 1024),
            frames: 0,
            records: 0,
        };
        while corpus.bytes.len() < len {
            if !codec8_only && corpus.frames % 64 == 63 {
                corpus.bytes.extend_from_slice(&response);
            } else {
                let device = &mut devices[corpus.frames as usize % DEVICES];
                let packet = device.next_frame().expect("a record fits in a frame");
                corpus.bytes.extend_from_slice(&packet.bytes);
                corpus.records += u64::from(packet.records);
            }
            corpus.frames += 1;
        }
        corpus
    }
}
