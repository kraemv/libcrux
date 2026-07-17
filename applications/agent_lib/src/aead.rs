pub use libcrux_chacha20poly1305::{NONCE_LEN as CHACHA_NONCE_LEN, TAG_LEN as CHACHA_TAG_LEN, Key as ChaCha20Key, Tag as ChaCha20Tag};
use zeroize::ZeroizeOnDrop;
use crate::Error;

pub struct ChaCha20Poly1305;
pub struct AeadNonce<const N: usize>([u8; N]);

pub struct AeadTag<const N: usize>([u8; N]);

#[derive(ZeroizeOnDrop)]
pub struct ChaCha20Poly1305Key([u8; 32]);

impl ChaCha20Poly1305Key {
    pub fn encrypt_msg<'a>(
        &self,
        ct: &'a mut [u8],
        nonce: AeadNonce<CHACHA_NONCE_LEN>,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(&'a [u8], AeadTag<CHACHA_TAG_LEN>), crate::Error>
    {
        let mut tag = ChaCha20Tag::from([0u8; CHACHA_TAG_LEN]);
        let nonce_bytes: [u8; CHACHA_NONCE_LEN] = nonce.into();
        let nonce = nonce_bytes.into();
        let key = ChaCha20Key::from(self.0);
        key.encrypt(ct, &mut tag, &nonce, aad, plaintext)
            .map(|()| (&ct[..], (*tag.as_ref()).into()))
            .map_err(|_| Error::AEAD)
    }

    pub fn decrypt_msg<'a>(
        &self,
        pt: &'a mut [u8],
        nonce: AeadNonce<CHACHA_NONCE_LEN>,
        aad: &[u8],
        ciphertext: &[u8],
        tag: AeadTag<CHACHA_TAG_LEN>,
    ) -> Result<&'a [u8], crate::Error> {
        let nonce: [u8; CHACHA_NONCE_LEN] = nonce.into();
        let tag: [u8; CHACHA_TAG_LEN] = tag.into();
        let key = ChaCha20Key::from(self.0);
        key.decrypt(pt, &nonce.into(), aad, ciphertext, &tag.into())
            .map_err(map_libcrux_decrypt_error)
            .map(|()| &pt[..])
    }
}

fn map_libcrux_decrypt_error(err: libcrux_traits::aead::arrayref::DecryptError) -> Error {
    match err {
        libcrux_traits::aead::arrayref::DecryptError::InvalidTag => Error::InvalidTag,
        libcrux_traits::aead::arrayref::DecryptError::Unknown => Error::AEAD,
        _ => Error::AEAD,
    }
}

impl<const N: usize> From<[u8; N]> for AeadNonce<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<AeadNonce<N>> for [u8; N] {
    fn from(value: AeadNonce<N>) -> Self {
        value.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for AeadNonce<N> {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(|bytes: [u8; N]| Self::from(bytes))
            .map_err(|_| crate::Error::AEAD)
    }
}

impl<const N: usize> AsRef<[u8]> for AeadNonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for AeadTag<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for ChaCha20Poly1305Key {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<AeadTag<N>> for [u8; N] {
    fn from(value: AeadTag<N>) -> Self {
        value.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for AeadTag<N> {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(|bytes: [u8; N]| Self::from(bytes))
            .map_err(|_| crate::Error::AEAD)
    }
}

impl<const N: usize> AsRef<[u8]> for AeadTag<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
