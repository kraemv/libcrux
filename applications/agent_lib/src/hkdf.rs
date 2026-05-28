use crate::kx::SharedKey;
use crate::Error;
use crate::InnerRndBytes;
use std::vec::Vec as std_vec;
use libcrux_hkdf as hkdf;

pub(crate) const SHA2_256_LEN: usize = hkdf::Algorithm::hash_len(hkdf::Algorithm::Sha256);

pub struct PseudorandomKey ([u8; 32]);
#[derive(Clone)]
pub struct RandomBytes (InnerRndBytes);

impl SharedKey {

    pub fn sha2_256_hkdf_extract(&self, salt: Option<&[u8]>) -> Result<PseudorandomKey, Error> {
        let salt = salt.unwrap_or(&[0u8; SHA2_256_LEN]);
        let mut prk = [0u8; 32];
        hkdf::Hkdf::<hkdf::Sha2_256>::extract_arrayref(&mut prk, salt, self.as_ref())
            .map(|_| PseudorandomKey(prk))
            .map_err(|_| Error::HKDF)
    }
}

impl PseudorandomKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn sha2_256_hkdf_expand(&self, info: &[u8], outlen: usize) -> Result<RandomBytes, Error> {
        let mut okm = InnerRndBytes::new();
        let okm_ref = okm.get_mut(0..outlen).ok_or(Error::HKDF)?;
        hkdf::Hkdf::<hkdf::Sha2_256>::expand_arrayref(okm_ref, &self.0, info)
            .map(|_| RandomBytes(okm))
            .map_err(|_| Error::HKDF)
    }
}

impl RandomBytes {
    pub fn into_vec(&self) -> std_vec<u8> {
        self.0.to_vec()
    }

    pub(crate) fn copy_inner(&self) -> InnerRndBytes {
        self.0.clone()
    }
}

impl AsRef<[u8; 32]> for PseudorandomKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for RandomBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for RandomBytes {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        InnerRndBytes::from_slice(bytes)
            .map(Self)
            .map_err(|_| Error::HKDF)
    }
}