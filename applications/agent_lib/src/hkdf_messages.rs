use std::marker::PhantomData;

use crate::{Error, ID};
use zerocopy::*;

pub struct HkdfExtractPublicSalt{}
pub struct HkdfExtractSecretSalt{}
pub struct HkdfExpand{}

#[derive(Clone, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum HkdfExtractHeader {
    KeyAbsent,
    KeyExists,
}

pub struct HkdfExtractPublicRequest<'a> {
    id: ID,
    salt: &'a [u8],
}

pub struct HkdfExtractSecretRequest {
    salt: ID,
    id: Option<ID>,
}

// Wire: [id: ID][output_len: u32 LE][info: remaining bytes]
pub struct HkdfExpandRequest<'a> {
    id: ID,
    output_len: usize,
    info: &'a [u8],
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct HkdfResponse<Event> {
    id: ID,
    event: PhantomData<Event>,
}

impl<'a> HkdfExtractPublicRequest<'a> {
    pub fn new(id: ID, salt: &'a [u8]) -> Self 
    {
        Self { id, salt }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_salt(&self) -> &'a [u8] {
        self.salt
    }
}

impl HkdfExtractSecretRequest {
    pub fn new(id: Option<ID>, salt: ID) -> Self 
    {
        Self { id, salt }
    }

    pub fn get_id(&self) -> Option<&ID> {
        self.id.as_ref()
    }

    pub fn get_salt(&self) -> &ID {
        &self.salt
    }
}

impl<'a> TryFrom<&'a [u8]> for HkdfExtractPublicRequest<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {

        let (id, salt) = ID::try_read_from_prefix(bytes).map_err(|_| Error::MalformedRequest)?;

        Ok(Self {id, salt })
    }
}

const ID_SIZE: usize = size_of::<ID>();

impl<'a> TryFrom<&'a [u8]> for HkdfExtractSecretRequest {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (salt, key) = match bytes.len() {
            ID_SIZE => (ID::try_read_from_bytes(bytes).map_err(|_| Error::MalformedRequest)?, None),
            _ => {
                let (salt, bytes) = ID::try_read_from_prefix(bytes).map_err(|_| Error::MalformedRequest)?;
                let key = ID::try_read_from_bytes(bytes).map_err(|_| Error::MalformedRequest)?;
                (salt, Some(key))
            }
        };

        Ok(Self { salt, id: key })
    }
}


impl<'a> HkdfExpandRequest<'a> {
    pub fn new(id: ID, output_len: usize, info: &'a [u8]) -> Self {
        Self { id, output_len, info }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_output_len(&self) -> usize {
        self.output_len
    }

    pub fn get_info(&self) -> &[u8] {
        self.info
    }
}

impl<'a> TryFrom<&'a [u8]> for HkdfExpandRequest<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, bytes) = ID::try_read_from_prefix(bytes).map_err(|_| Error::MalformedRequest)?;
        let (output_len, info) = usize::try_read_from_prefix(bytes).map_err(|_| Error::MalformedRequest)?;

        Ok(Self { id, output_len, info })
    }
}

impl From<HkdfExpandRequest<'_>> for Vec<u8> {
    fn from(request: HkdfExpandRequest<'_>) -> Self {
        let mut result = Vec::new();
        result.extend_from_slice(request.id.as_ref());
        result.extend_from_slice(&(request.output_len as u32).to_le_bytes());
        result.extend_from_slice(request.info);
        result
    }
}

impl<Event> HkdfResponse<Event> {
    pub fn new(id: ID) -> Self {
        Self { id, event: PhantomData }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }
}
