use std::{
    io::{Read, Write},
    marker::PhantomData,
    net::TcpStream,
};

use cliplink_common::{PACKET_SIZE, Packet, PacketError};
use cliplink_crypto::{Aes256, GCM_AUTHENTICATION_TAG_SIZE, NONCE_SIZE, RsaPubKey};

pub enum Input<'a> {
    SshHandshake(&'a [u8]),
}

pub enum Output {
    SshHandshakeAck(Vec<u8>),
    SshHandshakeDeny(&'static str),
}

impl<'a> TryFrom<&'a Packet> for Input<'a> {
    type Error = PacketError;

    fn try_from(packet: &'a Packet) -> Result<Self, Self::Error> {
        match packet.ty()? {
            b"sshsyn" => Ok(Self::SshHandshake(packet.payload()?)),
            _ => unimplemented!("unexpected type"),
        }
    }
}

//impl From<Output> for OwnedPacket {
//    fn from(pl: Output) -> Self {
//        match pl {
//            Output::SshHandshakeAck(pl) => OwnedPacket::new(b"sshsynack".fill(0x0), pl),
//            Output::SshHandshakeDeny(pl) => OwnedPacket::new("sshsyndeny".into(), pl.into()),
//            _ => unimplemented!("unexpected type"),
//        }
//    }
//}

impl<'a> From<&'a Output> for Packet {
    fn from(pl: &'a Output) -> Self {
        match pl {
            Output::SshHandshakeAck(pl) => Packet::new(b"sshsynack", pl),
            Output::SshHandshakeDeny(pl) => Packet::new(b"sshsyndeny", pl.as_bytes()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("unsupported key type")]
    UnsupportedKeyType,

    #[error(transparent)]
    Aes(#[from] cliplink_crypto::AesError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    PacketError(#[from] PacketError),

    #[error(transparent)]
    RsaError(#[from] cliplink_crypto::RsaError),
}

pub struct Handshake;
pub struct HandshakeAck;
pub struct Secure;

pub struct Connection<State> {
    aes_key: Option<Aes256>,
    rsa_pub_key: Option<RsaPubKey>,
    phantom: PhantomData<State>,
    stream: TcpStream,
}

impl<T> Connection<T> {
    fn mutate<N>(self) -> Connection<N> {
        Connection {
            aes_key: self.aes_key,
            rsa_pub_key: self.rsa_pub_key,
            phantom: PhantomData::<N>,
            stream: self.stream,
        }
    }

    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let buf_len = match self.stream.read(buf) {
            Ok(buf_len) => buf_len,
            Err(err) => {
                eprintln!("read failure, closing socket: {err:?}");
                self.stream
                    .shutdown(std::net::Shutdown::Both)
                    .expect("failed to shutdown");

                panic!("{err}");
            }
        };

        buf[buf_len..].fill(0x0);

        dbg!("read", buf.len(), buf_len);
        Ok(buf_len)
    }

    fn write_bytes(&mut self, buf: &[u8]) -> Result<usize, ConnectionError> {
        let buf_len = self.stream.write(&buf)?;

        dbg!("write", buf.len(), buf_len);
        Ok(buf_len)
    }

    fn write_output(&mut self, output: Output) -> Result<usize, ConnectionError> {
        self.write_bytes(Packet::from(&output).as_bytes())
    }
}

// sshsyn > sshsynack | sshsyndeny
//
// client                  | server
// pubkeysyn (pub ssh key) > pubkeyack
// enckeyack               < enckey (encrypted)
// copy   (payload)        > copyack
// paste                   < pasteack (payload)
impl Connection<Handshake> {
    pub fn from(stream: TcpStream) -> Self {
        Self {
            aes_key: None,
            rsa_pub_key: None,
            phantom: PhantomData::<Handshake>,
            stream,
        }
    }

    pub fn validate_ssh_key(
        mut self,
        packet: &Packet,
    ) -> Result<Connection<HandshakeAck>, ConnectionError> {
        let Input::SshHandshake(pub_key) = Input::try_from(packet)? else {
            self.write_output(Output::SshHandshakeDeny("unsupported key type"))?;

            return Err(ConnectionError::UnsupportedKeyType);
        };

        self.rsa_pub_key = Some(RsaPubKey::from_openssh(pub_key)?);

        Ok(self.mutate::<HandshakeAck>())
    }
}

impl Connection<HandshakeAck> {
    pub fn gen_aes256_key(mut self) -> Result<Connection<Secure>, ConnectionError> {
        let rsa_pub_key = self.rsa_pub_key.as_ref().expect("no rsa key available");

        let aes_key = Aes256::new()?;
        let aes_key_enc_buf = rsa_pub_key.encrypt_pkcs1v15(aes_key.as_bytes())?;

        self.write_output(Output::SshHandshakeAck(aes_key_enc_buf))?;

        self.aes_key = Some(aes_key);

        Ok(self.mutate::<Secure>())
    }
}

impl Connection<Secure> {
    pub fn id(&self) -> Result<String, ConnectionError> {
        Ok(self
            .rsa_pub_key
            .as_ref()
            .expect("no rsa key available")
            .to_openssh(None)?)
    }

    pub fn read_packet_sec(&mut self) -> Result<Packet, ConnectionError> {
        let mut buf = [0u8; NONCE_SIZE + PACKET_SIZE + GCM_AUTHENTICATION_TAG_SIZE];
        let _ = self.read_bytes(&mut buf)?;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&buf[0..NONCE_SIZE]);

        let aes_key = self.aes_key.as_ref().expect("no aes key available");
        let mut dec_buf = [0u8; PACKET_SIZE];
        dec_buf.copy_from_slice(&aes_key.decrypt(nonce, &buf[NONCE_SIZE..])?);

        Ok(Packet::from_bytes(&dec_buf))
    }

    pub fn write_packet_sec(&mut self, packet: Packet) -> Result<usize, ConnectionError> {
        let aes_key = self.aes_key.as_ref().expect("no aes key available");

        let (nonce, enc_buf) = aes_key.encrypt(packet.as_bytes())?;
        dbg!(nonce.len(), enc_buf.len());

        let mut inline_buf = Vec::with_capacity(nonce.len() + enc_buf.len());
        inline_buf.extend_from_slice(&nonce);
        inline_buf.extend_from_slice(&enc_buf);

        let buf_len = self.write_bytes(&inline_buf)?;

        Ok(buf_len)
    }
}
