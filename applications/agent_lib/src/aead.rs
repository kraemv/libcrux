pub use libcrux_chacha20poly1305::{NONCE_LEN as CHACHA_NONCE_LEN, TAG_LEN as CHACHA_TAG_LEN};

pub struct ChaCha20Poly1305;
pub struct AeadNonce<const N: usize>([u8; N]);

pub struct AeadTag<const N: usize>([u8; N]);

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
        value.try_into()
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

impl<const N: usize> From<AeadTag<N>> for [u8; N] {
    fn from(value: AeadTag<N>) -> Self {
        value.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for AeadTag<N> {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into()
            .map(|bytes: [u8; N]| Self::from(bytes))
            .map_err(|_| crate::Error::AEAD)
    }
}

impl<const N: usize> AsRef<[u8]> for AeadTag<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}