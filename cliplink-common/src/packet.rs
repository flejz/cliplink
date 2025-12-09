use std::{ops::Deref, str::Utf8Error};

use crate::slice;

/// Packets are `PACKET_SIZE` bytes long structures compose of header and content bytes, as follows
/// * type length: 8 bytes (big-endian)
/// * payload length: 8 bytes (big-endian)
/// * type: 16 bytes
/// * payload: 992
///
/// **Packet structure:**
///
/// |-----------------------------------------------|
/// |    type len (2b)   |     type (24b)           |
/// |-----------------------------------------------|
/// |  payload len (2b)  |  payload  (remaining b)  | **up to PACKET_SIZE**
/// |-----------------------------------------------|
//pub const PACKET_SIZE: usize = 2048;
pub const PACKET_SIZE: usize = 1024;

pub const SECTION_TYPE_LEN_OFFSET: usize = 0;
pub const SECTION_TYPE_LEN_SIZE: usize = 2;
pub const SECTION_TYPE_OFFSET: usize = SECTION_TYPE_LEN_OFFSET + SECTION_TYPE_LEN_SIZE;
pub const SECTION_TYPE_SIZE: usize = 24;

pub const SECTION_PAYLOAD_LEN_OFFSET: usize = SECTION_TYPE_OFFSET + SECTION_TYPE_SIZE;
pub const SECTION_PAYLOAD_LEN_SIZE: usize = 2;
pub const SECTION_PAYLOAD_OFFSET: usize = SECTION_PAYLOAD_LEN_OFFSET + SECTION_PAYLOAD_LEN_SIZE;
pub const SECTION_PAYLOAD_SIZE: usize = PACKET_SIZE - SECTION_PAYLOAD_OFFSET;

macro_rules! byte_slice_factory {
    ($len: expr) => {
        paste::paste! {
            fn [<to_sized_ $len:lower _byte_slice>](src: &[u8]) -> [u8; $len] {
                let mut out = [0u8; $len];
                let n = src.len().min($len);
                out[..n].copy_from_slice(&src[..n]);
                out
            }
        }
    };
}

byte_slice_factory!(8);
byte_slice_factory!(SECTION_TYPE_LEN_SIZE);
byte_slice_factory!(SECTION_TYPE_SIZE);
byte_slice_factory!(SECTION_PAYLOAD_LEN_SIZE);
byte_slice_factory!(SECTION_PAYLOAD_SIZE);

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum PacketError {
    #[error("section overflow")]
    SectionOverflow,

    #[error("section overflow")]
    BufferOverflow,

    #[error(transparent)]
    ParsingError(#[from] Utf8Error),
}

/// Transport packet structure
#[derive(Debug, PartialEq)]
pub struct Packet {
    pub buf: [u8; PACKET_SIZE],
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            buf: [0u8; PACKET_SIZE],
        }
    }
}

impl Deref for Packet {
    type Target = [u8; PACKET_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl Packet {
    pub fn new(ty: &[u8], payload: &[u8]) -> Self {
        let mut packet = Packet::default();
        let buf = &mut packet.buf;

        slice!(buf[SECTION_TYPE_LEN_OFFSET; SECTION_TYPE_LEN_SIZE]).copy_from_slice(
            &to_sized_section_type_len_size_byte_slice(&ty.len().to_le_bytes()),
        );

        slice!(buf[SECTION_TYPE_OFFSET; SECTION_TYPE_SIZE])
            .copy_from_slice(&to_sized_section_type_size_byte_slice(&ty));

        slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_PAYLOAD_LEN_SIZE]).copy_from_slice(
            &to_sized_section_payload_len_size_byte_slice(&payload.len().to_le_bytes()),
        );

        slice!(buf[SECTION_PAYLOAD_OFFSET; SECTION_PAYLOAD_SIZE])
            .copy_from_slice(&to_sized_section_payload_size_byte_slice(&payload));

        packet
    }

    pub fn ty(&self) -> Result<&[u8], PacketError> {
        let buf = &self.buf;
        let buf_len = self.ty_len();

        if buf_len > SECTION_TYPE_SIZE {
            return Err(PacketError::SectionOverflow);
        }

        Ok(&slice!(buf[SECTION_TYPE_OFFSET; buf_len]))
    }

    pub fn ty_len(&self) -> usize {
        let buf = &self.buf;
        usize::from_le_bytes(to_sized_8_byte_slice(&slice!(buf[
                SECTION_TYPE_LEN_OFFSET;
                SECTION_TYPE_LEN_SIZE
        ])))
    }

    pub fn payload(&self) -> Result<&[u8], PacketError> {
        let buf = &self.buf;
        let buf_len = self.payload_len();

        dbg!(buf_len);

        if buf_len > SECTION_PAYLOAD_SIZE {
            return Err(PacketError::SectionOverflow);
        } else if SECTION_PAYLOAD_OFFSET + buf_len > PACKET_SIZE {
            return Err(PacketError::BufferOverflow);
        }

        Ok(&slice!(buf[SECTION_PAYLOAD_OFFSET; buf_len]))
    }

    pub fn payload_len(&self) -> usize {
        let buf = &self.buf;
        usize::from_le_bytes(to_sized_8_byte_slice(&slice!(buf[
                SECTION_PAYLOAD_LEN_OFFSET;
                SECTION_PAYLOAD_LEN_SIZE
        ])))
    }

    pub fn from_bytes(buf: &[u8; PACKET_SIZE]) -> Packet {
        let mut packet = Packet::default();
        packet.buf.copy_from_slice(buf);
        packet
    }

    pub fn as_bytes(&self) -> &[u8; PACKET_SIZE] {
        &self.buf
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Packet, PacketError, SECTION_PAYLOAD_LEN_OFFSET, SECTION_PAYLOAD_LEN_SIZE,
        SECTION_PAYLOAD_OFFSET, SECTION_PAYLOAD_SIZE, SECTION_TYPE_LEN_OFFSET,
        SECTION_TYPE_LEN_SIZE, SECTION_TYPE_OFFSET, SECTION_TYPE_SIZE, slice,
    };

    const BUF_TY_LEN: [u8; SECTION_TYPE_LEN_SIZE] = [3, 0];
    const BUF_TY: [u8; SECTION_TYPE_SIZE] = [
        115, 121, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    const BUF_PL_LEN: [u8; SECTION_PAYLOAD_LEN_SIZE] = [14, 0];
    const BUF_PL: [u8; 14] = [
        112, 117, 98, 108, 105, 99, 32, 107, 101, 121, 112, 97, 105, 114,
    ];

    #[test]
    fn from_bytes() {
        let mut buf = Packet::default().buf;
        slice!(buf[SECTION_TYPE_LEN_OFFSET; SECTION_TYPE_LEN_SIZE]).copy_from_slice(&BUF_TY_LEN);
        slice!(buf[SECTION_TYPE_OFFSET; SECTION_TYPE_SIZE]).copy_from_slice(&BUF_TY);
        slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_PAYLOAD_LEN_SIZE])
            .copy_from_slice(&BUF_PL_LEN);
        slice!(buf[SECTION_PAYLOAD_OFFSET; 14]).copy_from_slice(&BUF_PL);

        let probe = Packet::from_bytes(&buf);
        let packet = Packet::new(b"syn", b"public keypair");

        assert_eq!(probe, packet);
        assert_eq!(probe.ty().unwrap(), b"syn");
        assert_eq!(probe.payload().unwrap(), b"public keypair");
    }

    #[test]
    fn as_bytes() {
        let packet = Packet::new(b"syn", b"public keypair");
        let buf = packet.as_bytes();

        assert_eq!(slice!(buf[SECTION_TYPE_OFFSET; SECTION_TYPE_SIZE]), BUF_TY);
        assert_eq!(
            slice!(buf[SECTION_TYPE_LEN_OFFSET; SECTION_TYPE_LEN_SIZE]),
            BUF_TY_LEN
        );
        assert_eq!(
            slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_PAYLOAD_LEN_SIZE]),
            BUF_PL_LEN
        );
        assert_eq!(slice!(buf[SECTION_PAYLOAD_OFFSET; 14]), BUF_PL);

        assert_eq!(
            slice!(buf[SECTION_PAYLOAD_OFFSET + 14; SECTION_PAYLOAD_SIZE - 14]),
            [0u8; SECTION_PAYLOAD_SIZE - 14]
        );

        // overflowing strings long strings
        assert_eq!(
            Packet::new(b"syn", &b"public keypair".repeat(200))
                .payload()
                .unwrap_err(),
            PacketError::SectionOverflow
        );
    }
}
