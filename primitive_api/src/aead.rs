use libcrux_chacha20poly1305 as chacha20poly1305;
use libcrux_traits::aead::owned::Aead;

use crate::NetworkObject;

pub enum Error {
    Decrypt,
    Encrypt,
}

pub enum AEADAlgorithm{
    AesGcm128,
    ChaCha20Poly1305,
}

pub trait AEADKey<const KEY_LEN: usize, const TAG_LEN: usize, const NONCE_LEN: usize>: Send + Sync + for <'a> TryFrom<&'a[u8]> + Aead<KEY_LEN, TAG_LEN, NONCE_LEN>{
    type Ct<'a>;
    type Nonce: NetworkObject;

    fn encrypt(&self, ct: &mut Self::Ct, plaintext: &[u8], nonce: Self::Nonce, aad: &[u8]) -> Result<(), Error>;

    fn decrypt(&self, ct: Self::Ct, nonce: Self::Nonce, aad: &[u8]) -> Result<&[u8], Error>;

    fn scheme() -> AEADAlgorithm;
}

impl<'a> AEADKey<{chacha20poly1305::KEY_LEN}, {chacha20poly1305::TAG_LEN}, {chacha20poly1305::NONCE_LEN}> for chacha20poly1305::Key {
    type Ct = (&'a [u8], chacha20poly1305::Tag);
    type Nonce = chacha20poly1305::Nonce;

    fn encrypt(&self, ct: &mut Self::Ct, plaintext: &[u8], nonce: Self::Nonce, aad: &[u8]) -> Result<(), Error> {
        self.encrypt(&mut ct.0, &mut ct.1, &nonce, aad, plaintext)
            .map_err(|_| Error::Encrypt)
    }

    fn decrypt(&self, ct: Self::Ct, nonce: Self::Nonce, aad: &[u8]) -> Result<&[u8], Error> {
        self.decrypt(&mut ct.0, &nonce, aad, &ct.0, &ct.1)
            .map_err(|_| Error::Decrypt)
            .map(|()| &ct.0)
    }

    fn scheme() -> AEADAlgorithm {
        AEADAlgorithm::ChaCha20Poly1305
    }
}

impl NetworkObject for chacha20poly1305::Nonce {}