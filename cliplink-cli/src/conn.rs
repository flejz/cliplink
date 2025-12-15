use std::{
    io::{Read, Write},
    marker::PhantomData,
    net::TcpStream,
};

use cliplink_common::{PACKET_SIZE, Packet, PacketError};
use cliplink_crypto::{AES_256_SIZE, Aes256, GCM_AUTHENTICATION_TAG_SIZE, NONCE_SIZE, RsaPrivKey};

pub enum Input {
    SshHandshakeAck(Vec<u8>),
    SshHandshakeDeny,
}

pub enum Output<'a> {
    SshHandshake(&'a [u8]),
}

impl TryFrom<&Packet> for Input {
    type Error = PacketError;

    fn try_from(packet: &Packet) -> Result<Self, Self::Error> {
        match packet.ty()? {
            b"sshsynack" => Ok(Self::SshHandshakeAck(packet.payload()?.to_vec())),
            b"sshsyndeny" => Ok(Self::SshHandshakeDeny),
            _ => unimplemented!("unexpected type"),
        }
    }
}

impl<'a> From<&Output<'a>> for Packet {
    fn from(pl: &Output<'a>) -> Self {
        match pl {
            Output::SshHandshake(pl) => Packet::new(b"sshsyn", pl),
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
    rsa_priv_key: Option<RsaPrivKey>,
    phantom: PhantomData<State>,
    stream: TcpStream,
}

impl<T> Connection<T> {
    fn mutate<N>(self) -> Connection<N> {
        Connection {
            aes_key: self.aes_key,
            rsa_priv_key: self.rsa_priv_key,
            phantom: PhantomData::<N>,
            stream: self.stream,
        }
    }

    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), std::io::Error> {
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
        Ok(())
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
            rsa_priv_key: None,
            phantom: PhantomData::<Handshake>,
            stream,
        }
    }

    pub fn send_ssh_key(mut self) -> Result<Connection<HandshakeAck>, ConnectionError> {
        let rsa_priv_key = RsaPrivKey::default();
        let rsa_pub_key_openssh = rsa_priv_key.pub_key().to_openssh(None)?;

        self.write_output(Output::SshHandshake(rsa_pub_key_openssh.as_bytes()))?;

        self.rsa_priv_key = Some(rsa_priv_key);

        Ok(self.mutate::<HandshakeAck>())
    }
}

impl Connection<HandshakeAck> {
    pub fn parse_aes256_key(
        mut self,
        packet: &Packet,
    ) -> Result<Connection<Secure>, ConnectionError> {
        let Input::SshHandshakeAck(aes_key) = Input::try_from(packet)? else {
            return Err(ConnectionError::UnsupportedKeyType);
        };

        let rsa_priv_key = self.rsa_priv_key.as_ref().expect("no rsa key available");

        let aes_key_dec_buf = rsa_priv_key.decrypt_pkcs1v15(&aes_key)?;

        if aes_key_dec_buf.len() > AES_256_SIZE {
            panic!("aes256 incompatible");
        }

        let mut buf = [0u8; AES_256_SIZE];
        buf.copy_from_slice(&aes_key_dec_buf);

        self.aes_key = Aes256::try_from(buf)?.into();

        Ok(self.mutate::<Secure>())
    }
}

impl Connection<Secure> {
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
