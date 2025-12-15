use cliplink_common::{Packet, PacketError};

use crate::conn::{Connection, ConnectionError, Secure};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("wrong response {0:?}")]
    WrongResponse(String),

    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),

    #[error(transparent)]
    PacketError(#[from] PacketError),
}

pub struct Session(Connection<Secure>);

impl Session {
    pub fn new(conn: Connection<Secure>) -> Self {
        Self(conn)
    }

    pub fn copy(&mut self, _clip: Option<&String>) -> Result<Vec<u8>, SessionError> {
        self.0.write_packet_sec(Packet::new(b"copy", &[]))?;
        let packet = self.0.read_packet_sec()?;

        match packet.ty()? {
            b"copyack" => Ok(packet.payload()?.to_vec()),
            ty => Err(SessionError::WrongResponse(
                str::from_utf8(ty).unwrap_or_default().to_string(),
            )),
        }
    }

    pub fn paste(&mut self, _clip: Option<&String>, buf: Vec<u8>) -> Result<(), SessionError> {
        self.0.write_packet_sec(Packet::new(b"paste", &buf))?;
        let packet = self.0.read_packet_sec()?;

        match packet.ty()? {
            b"pasteack" => Ok(()),
            ty => Err(SessionError::WrongResponse(
                str::from_utf8(ty).unwrap_or_default().to_string(),
            )),
        }
    }
}
