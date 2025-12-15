use std::u8;

use cliplink_common::{Packet, PacketError};

use crate::{
    conn::{Connection, ConnectionError, Secure},
    repository::Repository,
};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("type not supported {0:?}")]
    TypeNotSupported(String),

    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),

    #[error(transparent)]
    PacketError(#[from] PacketError),

    #[error("{0:?}")]
    RepositoryError(String),
}

pub struct Session<E>(Connection<Secure>, Box<dyn Repository<Vec<u8>, E>>);

impl<E: std::error::Error> Session<E> {
    pub fn new(conn: Connection<Secure>, repo: Box<dyn Repository<Vec<u8>, E>>) -> Self {
        Self(conn, repo)
    }

    pub fn blocking_handle(&mut self) -> Result<(), SessionError> {
        loop {
            let packet = self.0.read_packet_sec()?;

            match packet.ty()? {
                b"copy" => {
                    println!("copy");
                    let payload = self
                        .1
                        .get(&self.0.id()?, None)
                        .map_err(|err| SessionError::RepositoryError(err.to_string()))?;

                    self.0.write_packet_sec(Packet::new(b"copyack", &payload))?;
                }
                b"paste" => {
                    println!("paste");
                    self.1
                        .patch(&self.0.id()?, None, packet.payload()?.to_vec())
                        .map_err(|err| SessionError::RepositoryError(err.to_string()))?;

                    self.0.write_packet_sec(Packet::new(b"pasteack", &[]))?;
                }
                b"term" => return Ok(()),
                ty => {
                    return Err(SessionError::TypeNotSupported(
                        str::from_utf8(ty).unwrap_or_default().to_string(),
                    ));
                }
            };
        }
    }
}
