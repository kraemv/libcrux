use libcrux_hmac;
use crate::{InnerRndBytes, hkdf::RandomBytes};
use zerocopy::*;

pub struct Sha2_256HMAC;

// A tag that holds its actual value
#[derive(PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct HmacSha256Mac ([u8; 32]);

#[derive(Clone)]
pub struct HmacSha256Key (InnerRndBytes);

impl HmacSha256Mac {
    pub fn new(mac: [u8; 32]) -> Self {
        Self(mac)
    }

    pub fn get_mac(&self) -> &[u8; 32] {
        &self.0
    }
}

impl HmacSha256Key {
    pub fn new(key: InnerRndBytes) -> Self {
        Self (key)
    }

    pub fn get_key(&self) -> &[u8] {
        &self.0
    }

    pub fn authenticate(
        &self,
        message: &[u8],
    ) -> HmacSha256Mac {
        let mut mac = [0u8; 32];
        libcrux_hmac::hmac_sha2_256(&mut mac, &self.0, message);
        HmacSha256Mac::new(mac)
    }
}

impl From<&RandomBytes> for HmacSha256Key{
    fn from(bytes: &RandomBytes) -> Self {
        Self(bytes.copy_inner())
    }
}

impl TryFrom<&[u8]> for HmacSha256Key {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        InnerRndBytes::try_from(value)
            .map(HmacSha256Key)
            .map_err(|_| crate::Error::MAC)
    }
}

impl TryFrom<&[u8]> for HmacSha256Mac {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into()
            .map(Self::new)
            .map_err(|_| Self::Error::MAC)
    }
}

impl AsRef<[u8]> for HmacSha256Mac {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}