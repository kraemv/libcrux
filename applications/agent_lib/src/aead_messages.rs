use std::marker::PhantomData;

use crate::{Error, ID};
use zerocopy::*;

// ---------------------------------------------------------------------------
// Export Nonce request / response
// ---------------------------------------------------------------------------

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct ExportNonceRequest {
    id: ID,
}

impl ExportNonceRequest {
    pub fn new(id: ID) -> Self {
        Self { id }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }
}

pub struct ExportNonceResponse {
    shk: [u8; 12],
}

impl ExportNonceResponse {
    pub fn new(shk: [u8; 12]) -> Self {
        Self { shk }
    }

    pub fn get_shk(&self) -> &[u8; 12] {
        &self.shk
    }
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

pub struct AeadEncryptRequest<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> {
    id: ID,
    nonce: [u8; NONCE_LEN],
    aad: &'a [u8],
    plaintext: &'a [u8],
    scheme: PhantomData<Scheme>,
}

pub struct AeadDecryptRequest<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> {
    tag: [u8; TAG_LEN],
    ciphertext: &'a [u8],
    id: ID,
    nonce: [u8; NONCE_LEN],
    aad: &'a [u8],
    scheme: PhantomData<Scheme>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AeadEncryptResponse<'a, Scheme, const TAG_LEN: usize> {
    tag: [u8; TAG_LEN],
    ciphertext: &'a [u8],
    scheme: PhantomData<Scheme>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AeadDecryptResponse<'a, Scheme> {
    plaintext: &'a [u8],
    scheme: PhantomData<Scheme>,
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>
{
    pub fn new(id: ID, plaintext: &'a [u8], nonce: [u8; NONCE_LEN], aad: &'a [u8]) -> Self {
        Self {
            id,
            nonce,
            aad,
            plaintext,
            scheme: PhantomData,
        }
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>
{
    pub fn get_aad(&self) -> &[u8] {
        self.aad
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn get_plaintext(&self) -> &[u8] {
        self.plaintext
    }
}

impl<'a, Scheme, const TAG_LEN: usize> AeadEncryptResponse<'a, Scheme, TAG_LEN> {
    pub fn from_parts(ciphertext: &'a [u8], tag: [u8; TAG_LEN]) -> Self {
        Self {
            tag,
            ciphertext,
            scheme: PhantomData,
        }
    }

    pub fn into_parts(self) -> (&'a [u8], [u8; TAG_LEN]) {
        (self.ciphertext, self.tag)
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> TryFrom<&'a mut [u8]>
    for AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>
{
    type Error = Error;

    fn try_from(request: &'a mut [u8]) -> Result<Self, Self::Error> {
        let (plaintext_len, request_slice) =
            usize::try_read_from_prefix(request).map_err(|_| Error::MalformedRequest)?;

        let (plaintext, request_slice) = request_slice
            .split_at_checked(plaintext_len)
            .ok_or(Error::MalformedRequest)?;

        let (id, request_slice) =
            ID::try_read_from_prefix(request_slice).map_err(|_| Error::MalformedRequest)?;

        let (nonce, aad) = <[u8; NONCE_LEN]>::try_read_from_prefix(request_slice)
            .map_err(|_| Error::MalformedRequest)?;

        Ok(Self {
            plaintext,
            id,
            nonce,
            aad,
            scheme: PhantomData,
        })
    }
}

impl<'a, Scheme, const TAG_LEN: usize> TryFrom<&'a [u8]>
    for AeadEncryptResponse<'a, Scheme, TAG_LEN>
{
    type Error = Error;

    fn try_from(response: &'a [u8]) -> Result<Self, Self::Error> {
        let (tag, ciphertext) = response
            .split_at_checked(TAG_LEN)
            .ok_or(Error::MalformedRequest)?;
        let tag: [u8; TAG_LEN] = tag.try_into().expect("No panic here!");
        Ok(Self {
            tag,
            ciphertext,
            scheme: PhantomData,
        })
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize>
    From<AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>> for Vec<u8>
{
    fn from(request: AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>) -> Self {
        let mut result = request.plaintext.len().as_bytes().to_vec();
        result.extend(request.plaintext);
        result.extend(request.id.as_bytes());
        result.extend(request.nonce.as_bytes());
        result.extend(request.aad);

        result
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<AeadEncryptResponse<'a, Scheme, TAG_LEN>> for Vec<u8> {
    fn from(response: AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        let mut result = response.tag.to_vec();
        result.extend(response.ciphertext.iter());
        result
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>
{
    pub fn new(
        id: ID,
        ciphertext: &'a [u8],
        tag: [u8; TAG_LEN],
        nonce: [u8; NONCE_LEN],
        aad: &'a [u8],
    ) -> Self {
        Self {
            tag,
            ciphertext,
            id,
            nonce,
            aad,
            scheme: PhantomData,
        }
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize>
    AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>
{
    pub fn get_aad(&self) -> &[u8] {
        self.aad
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn get_tag(&self) -> &[u8; TAG_LEN] {
        &self.tag
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> TryFrom<&'a mut [u8]>
    for AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>
{
    type Error = Error;

    fn try_from(request: &'a mut [u8]) -> Result<Self, Self::Error> {
        let (tag, request_slice) =
            <[u8; TAG_LEN]>::try_read_from_prefix(request).map_err(|_| Error::MalformedRequest)?;
        let (ciphertext_len, request_slice) =
            usize::try_read_from_prefix(request_slice).map_err(|_| Error::MalformedRequest)?;

        let (ciphertext, request_slice) = request_slice
            .split_at_checked(ciphertext_len)
            .ok_or(Error::MalformedRequest)?;

        let (id, request_slice) =
            ID::try_read_from_prefix(request_slice).map_err(|_| Error::MalformedRequest)?;

        let (nonce, aad) = <[u8; NONCE_LEN]>::try_read_from_prefix(request_slice)
            .map_err(|_| Error::MalformedRequest)?;

        Ok(Self {
            tag,
            ciphertext,
            id,
            nonce,
            aad,
            scheme: PhantomData,
        })
    }
}

impl<'a, Scheme> From<&'a [u8]> for AeadDecryptResponse<'a, Scheme> {
    fn from(response: &'a [u8]) -> Self {
        Self {
            plaintext: response,
            scheme: PhantomData,
        }
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize>
    From<AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>> for Vec<u8>
{
    fn from(request: AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>) -> Self {
        let mut result = request.tag.to_vec();
        result.extend(request.ciphertext.len().as_bytes());
        result.extend(request.ciphertext);
        result.extend(request.id.as_bytes());
        result.extend(request.nonce.as_bytes());
        result.extend(request.aad);

        result
    }
}

impl<Scheme> From<AeadDecryptResponse<'_, Scheme>> for Vec<u8> {
    fn from(response: AeadDecryptResponse<'_, Scheme>) -> Self {
        response.plaintext.to_vec()
    }
}

impl<Scheme> AsRef<[u8]> for AeadDecryptResponse<'_, Scheme> {
    fn as_ref(&self) -> &[u8] {
        self.plaintext
    }
}
