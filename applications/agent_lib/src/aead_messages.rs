use std::marker::PhantomData;

use crate::{Error, ID,};

use zerocopy::*;

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

pub struct ChaCha20Poly1305;
pub const CHACHA_TAG_LEN: usize = 16;
pub const CHACHA_NONCE_LEN: usize = 12;

pub struct AeadEncryptRequest<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> {
    id: ID,
    nonce: [u8; NONCE_LEN],
    aad_len: usize,
    ptxt_len: usize,
    aad: &'a [u8],
    plaintext: &'a [u8],
    response: AeadEncryptResponse<'a, Scheme, TAG_LEN>,
    scheme: PhantomData<Scheme>
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AeadEncryptResponse<'a, Scheme, const TAG_LEN: usize> {
    tag: [u8; TAG_LEN],
    ciphertext: &'a [u8],
    scheme: PhantomData<Scheme>,
}


impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN> {
    pub fn new(id: ID, plaintext: &'a [u8], nonce:[u8; NONCE_LEN] , aad: &'a [u8], response: AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        Self { id, nonce, aad_len: aad.len(), ptxt_len: plaintext.len(), aad, plaintext, response, scheme: PhantomData }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_plaintext(&self) -> &[u8] {
        self.plaintext
    }

    pub fn get_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn get_aad(&self) -> &[u8] {
        self.aad
    }

    pub fn into_response(self) -> AeadEncryptResponse<'a, Scheme, TAG_LEN> {
        self.response
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> TryFrom<&'a [u8]> for AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN> {
    type Error = Error;

    fn try_from(request: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, remainder) = request
            .split_at_checked(crate::ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id: ID = id.try_into().expect("No panic here!");
        let (nonce, remainder) = remainder
            .split_at_checked(NONCE_LEN)
            .ok_or(Error::MalformedRequest)?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("No panic here!");
        let (aad_len, remainder) = usize::try_read_from_prefix(remainder).map_err(|_| Error::MalformedRequest)?;
        let (ptxt_len, remainder) = usize::try_read_from_prefix(remainder).map_err(|_| Error::MalformedRequest)?;
        let (aad, remainder) = remainder
            .split_at_checked(aad_len)
            .ok_or(Error::MalformedRequest)?;
        let (plaintext, remainder) = remainder
            .split_at_checked(ptxt_len)
            .ok_or(Error::MalformedRequest)?;
        let response = AeadEncryptResponse::<'a, Scheme, TAG_LEN>::try_from(remainder).map_err(|_| Error::MalformedRequest)?;
        Ok(Self { id, nonce, aad_len, ptxt_len, aad, plaintext, response, scheme: PhantomData })
    }
}

impl<'a, Scheme, const TAG_LEN: usize> TryFrom<&'a [u8]> for AeadEncryptResponse<'a, Scheme, TAG_LEN> {
    type Error = Error;

    fn try_from(response: &'a [u8]) -> Result<Self, Self::Error> {
        let (tag, ciphertext) = response
            .split_at_checked(TAG_LEN)
            .ok_or(Error::MalformedRequest)?;
        let tag: [u8; TAG_LEN] = tag.try_into().expect("No panic here!");
        Ok(Self { tag, ciphertext, scheme: PhantomData })
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> From<AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>> for Vec<u8>
{
    fn from(request: AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>) -> Self {
        let mut result = request.id.0.to_vec();
        result.extend(request.nonce.as_bytes());
        result.extend(request.aad_len.as_bytes());
        result.extend(request.ptxt_len.as_bytes());
        result.extend(request.aad);
        result.extend(request.plaintext);
        result.extend(request.response.tag);
        result.extend(request.response.ciphertext);
        result
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<AeadEncryptResponse<'a, Scheme, TAG_LEN>> for Vec<u8>
{
    fn from(response: AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        let mut result = response.tag.to_vec();
        result.extend(response.ciphertext);
        result
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<([u8; TAG_LEN], &'a [u8])> for AeadEncryptResponse<'a, Scheme, TAG_LEN> {
    fn from((tag, ciphertext): ([u8; TAG_LEN], &'a [u8])) -> Self {
        Self { tag, ciphertext, scheme: PhantomData }
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<&AeadEncryptResponse<'a, Scheme, TAG_LEN>> for ([u8; TAG_LEN], &'a [u8]) {
    fn from(resp: &AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        (resp.tag, resp.ciphertext)
    }
}