use std::marker::PhantomData;

use crate::Error;
use heapless::Vec;
use zerocopy::*;
use zeroize::ZeroizeOnDrop;

pub(crate) const ID_SIZE: usize = 31;
pub(crate) type InnerRndBytes = Vec<u8, 64>;

#[derive(
    Clone, Debug, Hash, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, ZeroizeOnDrop
)]
#[repr(C)]
pub struct ID([u8; ID_SIZE]);

impl TryFrom<&[u8]> for ID {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let id: [u8; ID_SIZE] = value.try_into().map_err(|_| Error::MalformedMessage)?;
        Ok(Self(id))
    }
}

impl From<[u8; ID_SIZE]> for ID {
    fn from(value: [u8; ID_SIZE]) -> Self {
        Self(value)
    }
}

impl From<ID> for [u8; ID_SIZE] {
    fn from(value: ID) -> Self {
        value.0
    }
}

impl AsRef<[u8; ID_SIZE]> for ID {
    fn as_ref(&self) -> &[u8; ID_SIZE] {
        &self.0
    }
}

pub enum ConversionError {
    MalformedID,
    NoIndex,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, ZeroizeOnDrop)]
#[repr(C)]
pub struct KeyID<Scheme> {
    id: ID,
    scheme: PhantomData<Scheme>,
}

impl<Scheme> KeyID<Scheme> {
    pub fn new(id: ID) -> Self {
        Self {
            id,
            scheme: PhantomData,
        }
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

impl<Scheme> From<[u8; ID_SIZE]> for KeyID<Scheme> {
    fn from(source: [u8; ID_SIZE]) -> Self {
        let id = ID::read_from_bytes(&source).unwrap();
        KeyID::<Scheme> {
            id,
            scheme: PhantomData,
        }
    }
}

impl<Scheme> From<KeyID<Scheme>> for [u8; ID_SIZE] {
    fn from(value: KeyID<Scheme>) -> Self {
        *value.id.as_ref()
    }
}

impl<Schme> AsRef<[u8]> for KeyID<Schme> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
