use zerocopy::*;
use heapless::Vec;

#[derive(Clone, Debug, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum Error {
    Derive,
    DuplicateKey,
    Encoding,
    IO,
    HKDF,
    KeyExchange,
    MAC,
    MalformedRequest,
    MalformedResponse,
    NoAgent,
    PublicKey,
    Signing,
    UnknownID,
    Unsupported,
}

pub(crate) const ID_SIZE: usize = 32;
pub(crate) type InnerRndBytes = Vec<u8, 64>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct ID([u8; ID_SIZE]); 

impl TryFrom<&[u8]> for ID {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let id: [u8; ID_SIZE] = value.try_into().map_err(|_| Error::MalformedRequest)?;
        Ok(Self(id))
    }
}

impl From<[u8; 32]> for ID {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 32]> for ID {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

pub mod aead_messages;
pub mod agent;
pub mod ipc;
pub mod hmac;
pub mod hmac_messages;
pub mod kex_messages;
pub mod key_store;
pub mod kx;
pub mod hkdf;
pub mod hkdf_messages;
pub mod messages;
pub mod signatures;
pub mod signing_messages;
