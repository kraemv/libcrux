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

pub struct HkdfExtractRequest<Salt> {
    header: HkdfExtractHeader,
    id: Option<ID>,
    salt: Option<Salt>,
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

impl<Salt> HkdfExtractRequest<Salt> {
    pub fn new(id: Option<ID>, salt: Option<Salt>) -> Self 
    {
        let header = match id {
            None => HkdfExtractHeader::KeyAbsent,
            Some(_) => HkdfExtractHeader::KeyExists,
        };
        Self { header, id, salt }
    }

    pub fn get_id(&self) -> Option<&ID> {
        self.id.as_ref()
    }

    pub fn get_header(&self) -> &HkdfExtractHeader {
        &self.header
    }
}

impl HkdfExtractRequest<ID> {
    pub fn get_salt(&self) -> Option<&ID> {
        self.salt.as_ref()
    }
}

impl HkdfExtractRequest<&[u8]> {
    pub fn get_salt(&self) -> Option<&[u8]> {
        self.salt
    }
}

impl<'a> TryFrom<&'a [u8]> for HkdfExtractRequest<ID> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (header, bytes) = HkdfExtractHeader::try_read_from_prefix(bytes).map_err(|_| Error::MalformedRequest)?;
        let (id, salt) = match header {
            HkdfExtractHeader::KeyAbsent => (None, bytes),
            HkdfExtractHeader::KeyExists => ID::try_read_from_prefix(bytes).map(|(id, bytes)| (Some(id), bytes)).map_err(|_| Error::MalformedRequest)?,
        };
        let salt = match salt.first() {
            None => None,
            Some(_) => Some(ID::try_read_from_bytes(salt).map_err(|_| Error::MalformedRequest)?),
        };

        Ok(Self { header, id, salt })
    }
}

impl<'a> TryFrom<&'a [u8]> for HkdfExtractRequest<&'a [u8]> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (header, bytes) = HkdfExtractHeader::try_read_from_prefix(bytes).map_err(|_| Error::MalformedRequest)?;
        let (id, salt) = match header {
            HkdfExtractHeader::KeyAbsent => (None, bytes),
            HkdfExtractHeader::KeyExists => ID::try_read_from_prefix(bytes).map(|(id, bytes)| (Some(id), bytes)).map_err(|_| Error::MalformedRequest)?,
        };
        let salt = salt.first().map(|_| salt);

        Ok(Self { header, id, salt })
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
