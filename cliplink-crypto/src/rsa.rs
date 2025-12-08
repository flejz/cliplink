use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use ssh_key::{private::KeypairData, public::KeyData};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("key not supported")]
    KeyNotSupported,

    #[error("minimum key size is 2048 bytes")]
    MinimumKeySize2048,

    #[error(transparent)]
    RsaError(#[from] rsa::Error),

    #[error(transparent)]
    SshKeyError(#[from] ssh_key::Error),
}

pub struct RsaPubKey(RsaPublicKey);

impl RsaPubKey {
    pub fn from_openssh(pub_key: &str) -> Result<Self, Error> {
        let pub_key = ssh_key::public::PublicKey::from_openssh(pub_key)?;

        let rsa = match pub_key.key_data() {
            KeyData::Rsa(rsa) => rsa,
            _ => return Err(Error::KeyNotSupported),
        };

        let rsa = RsaPublicKey::new(
            BigUint::from_bytes_be(rsa.n.as_bytes()),
            BigUint::from_bytes_be(rsa.e.as_bytes()),
        )?;

        Ok(Self(rsa))
    }

    pub fn encrypt_pkcs1v15(&self, buf: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = rand::thread_rng();
        Ok(self.0.encrypt(&mut rng, Pkcs1v15Encrypt, buf)?)
    }
}

pub struct RsaPrivKey(RsaPrivateKey);

impl RsaPrivKey {
    pub fn from_openssh(priv_key: &str) -> Result<Self, Error> {
        let priv_key = ssh_key::private::PrivateKey::from_openssh(priv_key)?;

        let rsa = match priv_key.key_data() {
            KeypairData::Rsa(key) => {
                // TODO: `ssh-key 0.6.7` fixed in the rc, but current version is wrong
                let ret = rsa::RsaPrivateKey::from_components(
                    rsa::BigUint::try_from(&key.public.n)?,
                    rsa::BigUint::try_from(&key.public.e)?,
                    rsa::BigUint::try_from(&key.private.d)?,
                    vec![
                        rsa::BigUint::try_from(&key.private.p)?,
                        rsa::BigUint::try_from(&key.private.q)?,
                    ],
                )?;

                if ret.size().saturating_mul(8) >= 2048 {
                    ret
                } else {
                    return Err(Error::MinimumKeySize2048);
                }
            }
            _ => return Err(Error::KeyNotSupported),
        };

        Ok(Self(rsa))
    }

    pub fn decrypt_pkcs1v15(&self, buf: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.decrypt(Pkcs1v15Encrypt, &buf)?)
    }
}

#[cfg(test)]
mod test {
    use std::sync::OnceLock;

    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

    use crate::{RsaPrivKey, RsaPubKey};

    fn rsa_keypair_1024() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey, String, String) {
        let mut rng = rand::thread_rng();
        let rsa_priv_key = OnceLock::new();
        let rsa_pub_key = rsa_priv_key
            .get_or_init(|| RsaPrivateKey::new(&mut rng, 2048).unwrap())
            .to_public_key();
        let rsa_priv_key = rsa_priv_key.get().unwrap().clone();

        let ssh_keypair = ssh_key::private::RsaKeypair::try_from(&rsa_priv_key).unwrap();
        let ssh_priv_key =
            ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Rsa(ssh_keypair), "").unwrap();

        (
            rsa_priv_key,
            rsa_pub_key,
            ssh_priv_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            ssh_priv_key.public_key().to_openssh().unwrap(),
        )
    }

    #[test]
    fn encrypt() {
        let (rsa_priv_key, _, _, pub_key_openssh) = rsa_keypair_1024();

        let pub_key = RsaPubKey::from_openssh(&pub_key_openssh).unwrap();

        let plain = "my plain text";
        let enc_buf = pub_key.encrypt_pkcs1v15(plain.as_bytes()).unwrap();
        let dec_buf = rsa_priv_key.decrypt(Pkcs1v15Encrypt, &enc_buf).unwrap();

        assert_ne!(enc_buf, plain.as_bytes());
        assert_eq!(dec_buf, plain.as_bytes());
    }

    #[test]
    fn decrypt() {
        let (_, rsa_pub_key, priv_key_openssh, _) = rsa_keypair_1024();

        let priv_key = RsaPrivKey::from_openssh(&priv_key_openssh).unwrap();

        let plain = "my plain text";
        let mut rng = rand::thread_rng();
        let enc_buf = rsa_pub_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, plain.as_bytes())
            .unwrap();
        let dec_buf = priv_key.decrypt_pkcs1v15(&enc_buf).unwrap();

        assert_ne!(enc_buf, plain.as_bytes());
        assert_eq!(dec_buf, plain.as_bytes());
    }
}
