use libcrux_chacha20poly1305 as chacha20poly1305;

use crate::NetworkObject;
use libcrux_agent::aead::{AeadNonce, AeadTag};

pub enum Error {
    Decrypt,
    Encrypt,
}

pub enum AEADAlgorithm{
    // AesGcm128,
    ChaCha20Poly1305,
}

pub trait AEADKey<const KEY_LEN: usize>: Send + Sync + From<[u8; KEY_LEN]>{
    type Tag: NetworkObject;
    type Nonce: NetworkObject;

    const SCHEME: AEADAlgorithm;

    fn encrypt<'a>(&self, ct: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<(&'a [u8], Self::Tag), Error>;

    fn decrypt<'a>(&self, pt: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], ct: &[u8], tag: Self::Tag) -> Result<&'a[u8], Error>;
}

impl AEADKey<{chacha20poly1305::KEY_LEN}> for chacha20poly1305::Key {
    type Tag = AeadTag<{chacha20poly1305::TAG_LEN}>;
    type Nonce = AeadNonce<{chacha20poly1305::NONCE_LEN}>;
    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;

    fn encrypt<'a>(&self, ct: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<(&'a [u8], Self::Tag), Error> {
        let mut tag = chacha20poly1305::Tag::from([0u8; chacha20poly1305::TAG_LEN]);
        let nonce_bytes: [u8; chacha20poly1305::NONCE_LEN] = nonce.into();
        let nonce = nonce_bytes.into();
        self.encrypt(ct, &mut tag, &nonce, aad, plaintext)
            .map(|()| (&ct[..], (*tag.as_ref()).into()))
            .map_err(|_| Error::Encrypt)
    }

    fn decrypt<'a>(&self, pt: &'a mut [u8], nonce: Self::Nonce, aad: &[u8], ct: &[u8], tag: Self::Tag) -> Result<&'a[u8], Error> {
        let nonce: [u8; chacha20poly1305::NONCE_LEN] = nonce.into();
        let tag: [u8; chacha20poly1305::TAG_LEN] = tag.into();
        self.decrypt(pt, &nonce.into(), aad, ct, &tag.into())
            .map_err(|_| Error::Decrypt)
            .map(|()| &pt[..])
    }
}

impl<const N: usize> NetworkObject for AeadNonce<N> {}
impl<const N: usize> NetworkObject for AeadTag<N> {}