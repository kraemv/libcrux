use std::marker::PhantomData;

use crate::{hmac::HmacSha256Mac, Error, ID};

use zerocopy::*;

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

pub struct HmacRequest<'a, Scheme> {
    id: ID,
    message: &'a [u8],
    _marker: PhantomData<Scheme>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct HmacResponse<MAC> {
    tag: MAC,
}

impl<'a, Scheme> HmacRequest<'a, Scheme> {
    pub fn new(id: ID, message: &'a [u8]) -> Self {
        Self {
            id,
            message,
            _marker: PhantomData,
        }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_payload(&self) -> &[u8] {
        self.message
    }
}

impl<'a, Scheme> TryFrom<&'a [u8]> for HmacRequest<'a, Scheme> {
    type Error = Error;

    fn try_from(request: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, message) = request
            .split_at_checked(crate::ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id: ID = id.try_into().expect("No panic here!");
        Ok(Self {
            id,
            message,
            _marker: PhantomData,
        })
    }
}

impl<'a, Scheme> From<HmacRequest<'a, Scheme>> for Vec<u8> {
    fn from(request: HmacRequest<Scheme>) -> Self {
        let mut result = request.id.as_ref().to_vec();
        result.extend(request.message);
        result
    }
}

impl From<HmacSha256Mac> for HmacResponse<HmacSha256Mac> {
    fn from(tag: HmacSha256Mac) -> Self {
        Self { tag }
    }
}

impl From<&HmacResponse<HmacSha256Mac>> for HmacSha256Mac {
    fn from(tag: &HmacResponse<HmacSha256Mac>) -> Self {
        HmacSha256Mac::new(*tag.tag.get_mac())
    }
}
