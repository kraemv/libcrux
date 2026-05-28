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