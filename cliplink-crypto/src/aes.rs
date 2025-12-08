use aes_gcm::{Aes256Gcm, AesGcm, KeyInit, Nonce, aead::Aead, aes};
use rand::{RngCore, rngs::OsRng};
use sha2::digest::{
    consts::{B0, B1},
    crypto_common,
    typenum::{UInt, UTerm},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0:?}")]
    AesGcmError(aes_gcm::Error),

    #[error(transparent)]
    InvalidLength(#[from] crypto_common::InvalidLength),
}

impl From<aes_gcm::Error> for Error {
    fn from(value: aes_gcm::Error) -> Self {
        Self::AesGcmError(value)
    }
}

pub struct Aes256(AesGcm<aes::Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>);

impl Aes256 {
    pub fn new() -> Result<Self, Error> {
        // 2) Generate random AES-256 key (32 bytes)
        let mut rng = OsRng;
        let mut aes_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut aes_key_bytes);
        let aes_cipher = Aes256Gcm::new_from_slice(&aes_key_bytes)?;

        Ok(Self(aes_cipher))
    }

    pub fn encrypt(&self, buf: &[u8]) -> Result<([u8; 12], Vec<u8>), Error> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let enc_buf = self.0.encrypt(Nonce::from_slice(&nonce), buf)?;

        Ok((nonce, enc_buf))
    }

    pub fn decrypt(&self, nonce: [u8; 12], buf: &[u8]) -> Result<Vec<u8>, Error> {
        let dec_buf = self.0.decrypt(Nonce::from_slice(&nonce), buf)?;

        Ok(dec_buf)
    }
}

#[cfg(test)]
mod test {
    use crate::Aes256;

    #[test]
    fn symmetric_encrypt_decrypt() {
        let aes_key = Aes256::new().unwrap();

        let plain = "my plain text";
        let (nonce, enc_buf) = aes_key.encrypt(plain.as_bytes()).unwrap();
        let dec_buf = aes_key.decrypt(nonce, &enc_buf).unwrap();

        assert_ne!(enc_buf, plain.as_bytes());
        assert_eq!(dec_buf, plain.as_bytes());
    }
}
