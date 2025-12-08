use std::{
    ops::{Deref, DerefMut},
    str::Utf8Error,
};

use crate::slice;

pub const PACKET_SIZE: usize = 2048;
pub const SECTION_LEN_SIZE: usize = 8;
pub const SECTION_TYPE_LEN_OFFSET: usize = 0;
pub const SECTION_TYPE_OFFSET: usize = 16;
pub const SECTION_TYPE_SIZE: usize = 16;
pub const SECTION_PAYLOAD_LEN_OFFSET: usize = 8;
pub const SECTION_PAYLOAD_OFFSET: usize = 32;
pub const SECTION_PAYLOAD_SIZE: usize = PACKET_SIZE - SECTION_PAYLOAD_OFFSET;

#[derive(Debug, PartialEq)]
pub enum PacketError {
    SectionOverflow,
    BufferOverflow,
    ParsingError,
}

impl From<Utf8Error> for PacketError {
    fn from(_: Utf8Error) -> Self {
        Self::ParsingError
    }
}

/// Transport packet structure
#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub ty: &'a str,
    pub pl: &'a str,
}

impl<'a> Default for Packet<'a> {
    fn default() -> Self {
        Self::new("", "")
    }
}

impl<'a> Packet<'a> {
    pub fn new(ty: &'a str, pl: &'a str) -> Self {
        Self { ty, pl }
    }

    pub fn new_buffer() -> [u8; PACKET_SIZE] {
        [0u8; PACKET_SIZE]
    }

    /// Packets are `PACKET_SIZE` bytes long structures compose of header and content bytes, as follows
    /// * type length: 8 bytes (big-endian)
    /// * payload length: 8 bytes (big-endian)
    /// * type: 16 bytes
    /// * payload: 992
    ///
    /// **Packet structure:**
    ///
    /// |----------------| **8 bytes**
    /// |--------------------------------| **16 bytes**
    ///
    /// |--------------------------------|
    /// |    type len    |  payload len  |
    /// |--------------------------------|
    /// |              type              |
    /// |--------------------------------| ---
    /// |                                |  |
    /// |             payload            |  | **up to PACKET_SIZE**
    /// |                                |  |
    /// |--------------------------------| ---
    pub fn from_bytes(buf: &'a [u8; PACKET_SIZE]) -> Result<Self, PacketError> {
        fn to_usize_bytes(src: &[u8]) -> [u8; 8] {
            let mut out = [0u8; 8];
            let n = src.len().min(8);
            out[..n].copy_from_slice(&src[..n]);
            out
        }

        let ty_len = usize::from_be_bytes(to_usize_bytes(&slice!(buf[
                SECTION_TYPE_LEN_OFFSET;
                SECTION_LEN_SIZE
        ])));

        if ty_len > SECTION_TYPE_SIZE {
            return Err(PacketError::SectionOverflow);
        }

        let pl_len = usize::from_be_bytes(to_usize_bytes(
            &slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_LEN_SIZE]),
        ));

        if pl_len > SECTION_PAYLOAD_SIZE {
            return Err(PacketError::SectionOverflow);
        } else if SECTION_PAYLOAD_OFFSET + pl_len > PACKET_SIZE {
            return Err(PacketError::BufferOverflow);
        }

        Ok(Self {
            ty: str::from_utf8(&slice!(buf[SECTION_TYPE_OFFSET; ty_len]))?,
            pl: str::from_utf8(&slice!(buf[SECTION_PAYLOAD_OFFSET; pl_len]))?,
        })
    }

    pub fn to_bytes(&'a self) -> Result<[u8; PACKET_SIZE], PacketError> {
        if self.ty.len() > SECTION_TYPE_SIZE {
            return Err(PacketError::SectionOverflow);
        } else if SECTION_PAYLOAD_OFFSET + self.pl.len() > PACKET_SIZE {
            return Err(PacketError::BufferOverflow);
        }

        let mut buf = [0u8; PACKET_SIZE];

        let ty_bytes = self.ty.as_bytes();
        let ty_bytes = [0u8; 16]
            .iter()
            .enumerate()
            .map(|(i, by)| if i < ty_bytes.len() { ty_bytes[i] } else { *by })
            .collect::<Vec<u8>>();

        slice!(buf[SECTION_TYPE_LEN_OFFSET; SECTION_LEN_SIZE])
            .copy_from_slice(self.ty.len().to_be_bytes().as_slice());
        slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_LEN_SIZE])
            .copy_from_slice(self.pl.len().to_be_bytes().as_slice());
        slice!(buf[SECTION_TYPE_OFFSET; SECTION_TYPE_SIZE]).copy_from_slice(ty_bytes.as_slice());
        slice!(buf[SECTION_PAYLOAD_OFFSET; self.pl.len()]).copy_from_slice(self.pl.as_bytes());

        Ok(buf)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        PACKET_SIZE, Packet, PacketError, SECTION_LEN_SIZE, SECTION_PAYLOAD_LEN_OFFSET,
        SECTION_PAYLOAD_OFFSET, SECTION_PAYLOAD_SIZE, SECTION_TYPE_LEN_OFFSET, SECTION_TYPE_OFFSET,
        SECTION_TYPE_SIZE, slice,
    };

    const BUF_TY_LEN: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 3];
    const BUF_TY: [u8; 16] = [115, 121, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    const BUF_PL_LEN: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 14];
    const BUF_PL: [u8; 14] = [
        112, 117, 98, 108, 105, 99, 32, 107, 101, 121, 112, 97, 105, 114,
    ];

    #[test]
    fn from_bytes() {
        let mut buf = Packet::new_buffer();
        slice!(buf[SECTION_TYPE_LEN_OFFSET; SECTION_LEN_SIZE]).copy_from_slice(&BUF_TY_LEN);
        slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_LEN_SIZE]).copy_from_slice(&BUF_PL_LEN);
        slice!(buf[SECTION_TYPE_OFFSET; SECTION_TYPE_SIZE]).copy_from_slice(&BUF_TY);
        slice!(buf[SECTION_PAYLOAD_OFFSET; 14]).copy_from_slice(&BUF_PL);

        assert_eq!(
            Packet::from_bytes(&buf).unwrap(),
            Packet::new("syn", "public keypair")
        );
    }

    #[test]
    fn to_bytes() {
        let buf = Packet::new("syn", "public keypair").to_bytes().unwrap();

        assert_eq!(
            slice!(buf[SECTION_TYPE_LEN_OFFSET; SECTION_LEN_SIZE]),
            BUF_TY_LEN
        );
        assert_eq!(
            slice!(buf[SECTION_PAYLOAD_LEN_OFFSET; SECTION_LEN_SIZE]),
            BUF_PL_LEN
        );
        assert_eq!(slice!(buf[SECTION_TYPE_OFFSET; SECTION_TYPE_SIZE]), BUF_TY);
        assert_eq!(slice!(buf[SECTION_PAYLOAD_OFFSET; 14]), BUF_PL);

        assert_eq!(
            slice!(buf[SECTION_PAYLOAD_OFFSET + 14; SECTION_PAYLOAD_SIZE - 14]),
            [0u8; SECTION_PAYLOAD_SIZE - 14]
        );

        // overflowing strings long strings
        assert_eq!(
            Packet::new(&"syn".repeat(6), "public keypair")
                .to_bytes()
                .unwrap_err(),
            PacketError::SectionOverflow
        );

        assert_eq!(
            Packet::new("syn", &"public keypair".repeat(71))
                .to_bytes()
                .unwrap_err(),
            PacketError::BufferOverflow
        );
    }
}
