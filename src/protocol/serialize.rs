//! `serde::Serialize` for views.
//!
//! Every view serializes exactly like its evaluated type, so switching
//! between the two doesn't change the output. [`Datagram`] is written here
//! too: it keeps its two IDs in one field, and serializes them as two.

use serde::ser::{Serialize, SerializeStruct, Serializer};

#[cfg(feature = "alloc")]
use super::Datagram;
use super::{
    AvlPacketView, AvlRecordView, DatagramView, FrameView, GprsMessageView, GprsPacketView,
    IoElementView, IoValueView,
};

/// Serializes the items of an iterator as a sequence.
struct Seq<I>(I);

impl<I> Serialize for Seq<I>
where
    I: Iterator + Clone,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.clone())
    }
}

impl Serialize for AvlPacketView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut packet = serializer.serialize_struct("AvlPacket", 2)?;
        packet.serialize_field("codec", &self.codec())?;
        packet.serialize_field("records", &Seq(self.records()))?;
        packet.end()
    }
}

impl Serialize for AvlRecordView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("AvlRecord", 6)?;
        record.serialize_field("timestamp", &self.timestamp())?;
        record.serialize_field("priority", &self.priority())?;
        record.serialize_field("gps", &self.gps())?;
        record.serialize_field("event_io_id", &self.event_io_id())?;
        record.serialize_field("generation_type", &self.generation_type())?;
        record.serialize_field("io_elements", &Seq(self.io_elements()))?;
        record.end()
    }
}

impl Serialize for IoElementView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut element = serializer.serialize_struct("IoElement", 2)?;
        element.serialize_field("id", &self.id())?;
        element.serialize_field("value", &self.value())?;
        element.end()
    }
}

impl Serialize for IoValueView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match *self {
            Self::U8(value) => serializer.serialize_newtype_variant("IoValue", 0, "U8", &value),
            Self::U16(value) => serializer.serialize_newtype_variant("IoValue", 1, "U16", &value),
            Self::U32(value) => serializer.serialize_newtype_variant("IoValue", 2, "U32", &value),
            Self::U64(value) => serializer.serialize_newtype_variant("IoValue", 3, "U64", &value),
            Self::Bytes(bytes) => serializer.serialize_newtype_variant(
                "IoValue",
                4,
                "Bytes",
                serde_bytes::Bytes::new(bytes),
            ),
        }
    }
}

impl Serialize for GprsPacketView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut packet = serializer.serialize_struct("GprsPacket", 2)?;
        packet.serialize_field("codec", &self.codec())?;
        packet.serialize_field("messages", &Seq(self.messages()))?;
        packet.end()
    }
}

impl Serialize for GprsMessageView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut message = serializer.serialize_struct("GprsMessage", 2)?;
        message.serialize_field("kind", &self.kind())?;
        message.serialize_field("payload", serde_bytes::Bytes::new(self.payload()))?;
        message.end()
    }
}

impl Serialize for FrameView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Avl(packet) => serializer.serialize_newtype_variant("Frame", 0, "Avl", packet),
            Self::Gprs(packet) => serializer.serialize_newtype_variant("Frame", 1, "Gprs", packet),
        }
    }
}

impl Serialize for DatagramView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut datagram = serializer.serialize_struct("Datagram", 4)?;
        datagram.serialize_field("packet_id", &self.packet_id())?;
        datagram.serialize_field("avl_packet_id", &self.avl_packet_id())?;
        datagram.serialize_field("imei", &self.imei())?;
        datagram.serialize_field("packet", &self.packet())?;
        datagram.end()
    }
}

#[cfg(feature = "alloc")]
impl Serialize for Datagram {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut datagram = serializer.serialize_struct("Datagram", 4)?;
        datagram.serialize_field("packet_id", &self.packet_id())?;
        datagram.serialize_field("avl_packet_id", &self.avl_packet_id())?;
        datagram.serialize_field("imei", self.imei())?;
        datagram.serialize_field("packet", self.packet())?;
        datagram.end()
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use std::vec;

    use crate::decoder::{take_datagram, take_frame};
    use crate::protocol::{Datagram, Frame};

    use crate::fixtures::{CODEC8_EXTENDED, CODEC12_COMMAND, CODEC16, UDP_CODEC8};

    const FRAMES: [&str; 3] = [CODEC8_EXTENDED, CODEC16, CODEC12_COMMAND];

    #[test]
    fn frame_views_serialize_like_evaluated_frames() {
        for hex in FRAMES {
            let bytes = hex::decode(hex).unwrap();
            let view = take_frame(&mut &bytes[..]).unwrap();
            assert_eq!(
                serde_json::to_value(view).unwrap(),
                serde_json::to_value(Frame::from(view)).unwrap(),
                "{hex}"
            );
        }
    }

    #[test]
    fn variable_io_serializes_like_evaluated_io() {
        let mut data = vec![0x8e, 0x01];
        data.extend_from_slice(&[0; 8 + 1 + 15]);
        data.extend_from_slice(&[
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 2, b'a', b'b',
        ]);
        data.push(0x01);
        let bytes = crate::decoder::tests::frame(&data);

        let view = take_frame(&mut &bytes[..]).unwrap();
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json, serde_json::to_value(Frame::from(view)).unwrap());
        assert_eq!(
            json["Avl"]["records"][0]["io_elements"][0]["value"],
            serde_json::json!({ "Bytes": [b'a', b'b'] })
        );
    }

    #[test]
    fn datagram_views_serialize_like_evaluated_datagrams() {
        let bytes = hex::decode(UDP_CODEC8).unwrap();
        let view = take_datagram(&mut &bytes[..]).unwrap();
        assert_eq!(
            serde_json::to_value(view).unwrap(),
            serde_json::to_value(Datagram::from(view)).unwrap()
        );
    }
}
