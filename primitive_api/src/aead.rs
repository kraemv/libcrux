use libcrux_chacha20poly1305 as chacha20poly1305;

use crate::{NetworkObject, KeyID};
use crate::provider::get_agent;
use libcrux_agent::aead::{AeadNonce, AeadTag};
pub use libcrux_agent::aead::ChaCha20Poly1305;

#[derive(Debug)]
pub enum Error {
    Internal(String),
    Decrypt,
    Encrypt,
}

pub enum AEADAlgorithm{
    // AesGcm128,
    ChaCha20Poly1305,
}

pub trait AEADKey<const KEY_SIZE: usize>: Send + Sync + From<[u8; KEY_SIZE]>{
    type Tag: NetworkObject;
    type Nonce: NetworkObject;

    const SCHEME: AEADAlgorithm;
    const KEY_LEN: usize;

    fn encrypt<'a>(&self, ct: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<(&'a [u8], Self::Tag), Error>;

    fn decrypt<'a>(&self, pt: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], ciphertext: &[u8], tag: Self::Tag) -> Result<&'a[u8], Error>;
}

impl AEADKey<{chacha20poly1305::KEY_LEN}> for chacha20poly1305::Key {
    type Tag = AeadTag<{chacha20poly1305::TAG_LEN}>;
    type Nonce = AeadNonce<{chacha20poly1305::NONCE_LEN}>;

    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;
    const KEY_LEN: usize = chacha20poly1305::KEY_LEN;


    fn encrypt<'a>(&self, ct: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<(&'a [u8], Self::Tag), Error> {
        let mut tag = chacha20poly1305::Tag::from([0u8; chacha20poly1305::TAG_LEN]);
        let nonce_bytes: [u8; chacha20poly1305::NONCE_LEN] = nonce.into();
        let nonce = nonce_bytes.into();
        self.encrypt(ct, &mut tag, &nonce, aad, plaintext)
            .map(|()| (&ct[..], (*tag.as_ref()).into()))
            .map_err(|_| Error::Encrypt)
    }

    fn decrypt<'a>(&self, pt: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], ciphertext: &[u8], tag: Self::Tag) -> Result<&'a[u8], Error> {
        let nonce: [u8; chacha20poly1305::NONCE_LEN] = nonce.into();
        let tag: [u8; chacha20poly1305::TAG_LEN] = tag.into();
        self.decrypt(pt, &nonce.into(), aad, ciphertext, &tag.into())
            .map_err(|_| Error::Decrypt)
            .map(|()| &pt[..])
    }
}

impl AEADKey<{size_of::<KeyID<ChaCha20Poly1305>>()}> for KeyID<ChaCha20Poly1305> {
    type Tag = AeadTag<{chacha20poly1305::TAG_LEN}>;
    type Nonce = AeadNonce<{chacha20poly1305::NONCE_LEN}>;

    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;
    const KEY_LEN: usize = chacha20poly1305::KEY_LEN;

    fn encrypt<'a>(&self, ct: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<(&'a [u8], Self::Tag), Error> {
        let agent = get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?;

        agent.chacha20poly1305_encrypt_for_id(self.get_id().clone(), ct, nonce.into(), plaintext, aad)
            .map_err(|_| Error::Encrypt)
    }

    fn decrypt<'a>(&self, pt: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], ciphertext: &[u8], tag: Self::Tag) -> Result<&'a[u8], Error> {
        let agent = get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?;

        agent.chacha20poly1305_decrypt_for_id(self.get_id().clone(), pt, nonce.into(), tag.into(), ciphertext, aad)
            .map_err(|_| Error::Decrypt)
    }
}

impl<const N: usize> NetworkObject for AeadNonce<N> {}
impl<const N: usize> NetworkObject for AeadTag<N> {}