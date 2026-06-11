use std::marker::PhantomData;

use zerocopy::*;
use heapless::Vec;

#[derive(Clone, Debug, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum Error {
    AEAD,
    Derive,
    DuplicateKey,
    Encoding,
    Expand,
    IO,
    HKDF,
    KeyExchange,
    MAC,
    MalformedRequest,
    MalformedResponse,
    NoAgent,
    PublicKey,
    Signing,
    Sync,
    UnknownID,
    Unsupported,
}

pub(crate) const ID_SIZE: usize = 32;
pub(crate) type InnerRndBytes = Vec<u8, 64>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
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

pub enum ConversionError {
    MalformedID,
    NoIndex,
}

const USIZE_SIZE: usize = size_of::<usize>();
const KEY_ID_SIZE: usize = ID_SIZE + USIZE_SIZE;

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct KeyID<Scheme> {
    id: ID,
    agent_idx: Usize<BigEndian>,
    scheme: PhantomData<Scheme>
}

impl<Scheme> KeyID<Scheme> {
    pub fn new(id: ID, agent_idx: usize) -> Self {
        Self { id, agent_idx: Usize::<BigEndian>::from_bytes(agent_idx.to_be_bytes()), scheme: PhantomData }
    }

    pub fn get_idx(&self) -> usize {
        self.agent_idx.get()
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }
}

impl<Scheme> TryFrom<&[u8]> for KeyID<Scheme> {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_read_from_bytes(value).map_err(|_| ConversionError::MalformedID)
    }
}

impl<Scheme> From<[u8; KEY_ID_SIZE]> for KeyID<Scheme> {
    fn from(value: [u8; KEY_ID_SIZE]) -> Self {
        let id= value.first_chunk::<ID_SIZE>().unwrap();
        let id = ID::from(*id);
        let agent_idx = Usize::<BigEndian>::from_bytes(value[32..].try_into().unwrap());
        KeyID::<Scheme> { id, agent_idx, scheme: PhantomData }
    }
}

impl<Scheme> From<KeyID<Scheme>> for [u8; KEY_ID_SIZE] {
    fn from(value: KeyID<Scheme>) -> Self {
        let mut out = [0u8; KEY_ID_SIZE];
        out[..32].copy_from_slice(value.id.as_ref());
        out[32..].copy_from_slice(value.agent_idx.as_bytes());
        out
    }
}

impl <Schme> AsRef<[u8]> for KeyID<Schme> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub mod aead;
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
