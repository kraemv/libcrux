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
    pub id: ID,
    pub nonce: [u8; NONCE_LEN],
    pub aad: &'a [u8],
    pub plaintext: &'a [u8],
    pub response: AeadEncryptResponse<'a, Scheme, TAG_LEN>,
    scheme: PhantomData<Scheme>
}

pub struct AeadDecryptRequest<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> {
    pub id: ID,
    pub nonce: [u8; NONCE_LEN],
    pub aad: &'a [u8],
    pub ciphertext: &'a [u8],
    pub tag: [u8; TAG_LEN],
    pub response: AeadDecryptResponse<'a, Scheme>,
    scheme: PhantomData<Scheme>
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AeadEncryptResponse<'a, Scheme, const TAG_LEN: usize> {
    tag: [u8; TAG_LEN],
    ciphertext: &'a mut [u8],
    scheme: PhantomData<Scheme>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AeadDecryptResponse<'a, Scheme> {
    plaintext: &'a mut [u8],
    scheme: PhantomData<Scheme>,
}


impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN> {
    pub fn new(id: ID, plaintext: &'a [u8], nonce:[u8; NONCE_LEN] , aad: &'a [u8], response: AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        Self { id, nonce, aad, plaintext, response, scheme: PhantomData }
    }

    pub fn into_response(self) -> AeadEncryptResponse<'a, Scheme, TAG_LEN> {
        self.response
    }
}

impl<'a, Scheme, const TAG_LEN: usize> AeadEncryptResponse<'a, Scheme, TAG_LEN> {
    pub fn get_ciphertext(&'a self) -> &'a [u8] {
        self.ciphertext
    }

    pub fn get_mut_ciphertext(&mut self) -> &mut[u8] {
        self.ciphertext
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> TryFrom<&'a mut [u8]> for AeadEncryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN> {
    type Error = Error;

    fn try_from(request: &'a mut [u8]) -> Result<Self, Self::Error> {
        let static_size = crate::ID_SIZE + NONCE_LEN;
        let usize_size = size_of::<usize>();
        let rest = &request[static_size ..];   // reborrow as shared

        let (aad_len, rest) = usize::try_read_from_prefix(rest)
            .map_err(|_| Error::MalformedRequest)?;
        let (ptxt_len, _) = usize::try_read_from_prefix(rest)
            .map_err(|_| Error::MalformedRequest)?;


        let request_size = static_size + 2*usize_size + aad_len + ptxt_len;
        let (request_slice, response_slice) = request
            .split_at_mut_checked(request_size)
            .ok_or(Error::MalformedRequest)?;

        let (id, request_slice) = request_slice
            .split_at_checked(crate::ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id: ID = id.try_into().expect("No panic here!");

        let (nonce, request_slice) = request_slice
            .split_at_checked(NONCE_LEN)
            .ok_or(Error::MalformedRequest)?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("No panic here!"); 

        // skip the two usize fields (already decoded above)
        let rest = &request_slice[2 * usize_size..];
        let (aad, plaintext) = rest
            .split_at_checked(aad_len)
            .ok_or(Error::MalformedRequest)?;

        let response = AeadEncryptResponse::<'a, Scheme, TAG_LEN>::try_from(response_slice).map_err(|_| Error::MalformedRequest)?;

        Ok(Self { id, nonce, aad, plaintext, response, scheme: PhantomData })
    }
}

impl<'a, Scheme, const TAG_LEN: usize> TryFrom<&'a mut [u8]> for AeadEncryptResponse<'a, Scheme, TAG_LEN> {
    type Error = Error;

    fn try_from(response: &'a mut [u8]) -> Result<Self, Self::Error> {
        let (tag, ciphertext) = response
            .split_at_mut_checked(TAG_LEN)
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
        result.extend(request.aad.len().as_bytes());
        result.extend(request.plaintext.len().as_bytes());
        result.extend(request.aad);
        result.extend(request.plaintext);
        result.extend(request.response.tag);
        result.extend(request.response.ciphertext.iter());
        result
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<AeadEncryptResponse<'a, Scheme, TAG_LEN>> for Vec<u8>
{
    fn from(response: AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        let mut result = response.tag.to_vec();
        result.extend(response.ciphertext.iter());
        result
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<(&'a mut [u8], [u8; TAG_LEN])> for AeadEncryptResponse<'a, Scheme, TAG_LEN> {
    fn from((ciphertext, tag, ): (&'a mut [u8], [u8; TAG_LEN])) -> Self {
        Self { tag, ciphertext, scheme: PhantomData }
    }
}

impl<'a, Scheme, const TAG_LEN: usize> From<&'a AeadEncryptResponse<'a, Scheme, TAG_LEN>> for ([u8; TAG_LEN], &'a [u8]) {
    fn from(resp: &'a AeadEncryptResponse<'a, Scheme, TAG_LEN>) -> Self {
        (resp.tag, resp.get_ciphertext())
    }
}


impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN> {
    pub fn new(id: ID, ciphertext: &'a [u8], nonce:[u8; NONCE_LEN], tag: [u8; TAG_LEN], aad: &'a [u8], response: AeadDecryptResponse<'a, Scheme>) -> Self {
        Self { id, nonce, aad, ciphertext, tag, response, scheme: PhantomData }
    }

    pub fn into_request(self) -> AeadDecryptResponse<'a, Scheme> {
        self.response
    }
}

impl<'a, Scheme> AeadDecryptResponse<'a, Scheme> {
    pub fn get_plaintext(&'a self) -> &'a [u8] {
        self.plaintext
    }

    pub fn get_mut_plaintext(&mut self) -> &mut[u8] {
        self.plaintext
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> TryFrom<&'a mut [u8]> for AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN> {
    type Error = Error;

    fn try_from(request: &'a mut [u8]) -> Result<Self, Self::Error> {
        let static_size = crate::ID_SIZE + NONCE_LEN + TAG_LEN;
        let usize_size = size_of::<usize>();
        let rest = &request[static_size ..];   // reborrow as shared

        let (aad_len, rest) = usize::try_read_from_prefix(rest)
            .map_err(|_| Error::MalformedRequest)?;
        let (ctxt_len, _) = usize::try_read_from_prefix(rest)
            .map_err(|_| Error::MalformedRequest)?;


        let request_size = static_size + 2*usize_size + aad_len + ctxt_len;
        let (request_slice, response_slice) = request
            .split_at_mut_checked(request_size)
            .ok_or(Error::MalformedRequest)?;

        let (id, request_slice) = request_slice
            .split_at_checked(crate::ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id: ID = id.try_into().expect("No panic here!");

        let (nonce, request_slice) = request_slice
            .split_at_checked(NONCE_LEN)
            .ok_or(Error::MalformedRequest)?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("No panic here!"); 

        let (tag, request_slice) = request_slice
            .split_at_checked(TAG_LEN)
            .ok_or(Error::MalformedRequest)?;
        let tag: [u8; TAG_LEN] = tag.try_into().expect("No panic here!"); 

        // skip the two usize fields (already decoded above)
        let rest = &request_slice[2 * usize_size..];
        let (aad, ciphertext) = rest
            .split_at_checked(aad_len)
            .ok_or(Error::MalformedRequest)?;

        let response = AeadDecryptResponse::<'a, Scheme>::from(response_slice);

        Ok(Self { id, nonce, tag, aad, ciphertext, response, scheme: PhantomData })
    }
}

impl<'a, Scheme, const NONCE_LEN: usize, const TAG_LEN: usize> From<AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>> for Vec<u8>
{
    fn from(request: AeadDecryptRequest<'a, Scheme, NONCE_LEN, TAG_LEN>) -> Self {
        let mut result = request.id.0.to_vec();
        result.extend(request.nonce.as_bytes());
        result.extend(request.tag.as_bytes());
        result.extend(request.aad.len().as_bytes());
        result.extend(request.ciphertext.len().as_bytes());
        result.extend(request.aad);
        result.extend(request.ciphertext);
        result.extend(request.response.plaintext.iter());
        result
    }
}

impl<'a, Scheme> From<AeadDecryptResponse<'a, Scheme>> for Vec<u8>
{
    fn from(response: AeadDecryptResponse<'a, Scheme>) -> Self {
        response.plaintext.to_vec()
    }
}

impl<'a, Scheme> From<&'a mut [u8]> for AeadDecryptResponse<'a, Scheme> {
    fn from(plaintext: &'a mut [u8]) -> Self {
        Self { plaintext, scheme: PhantomData }
    }
}

impl<'a, Scheme> AsRef<[u8]> for AeadDecryptResponse<'a, Scheme> {
    fn as_ref(&self) -> &[u8] {
        self.plaintext
    }
}