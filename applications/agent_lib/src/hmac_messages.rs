use std::marker::PhantomData;

use crate::{
    Error, ID, ID_SIZE, hmac::{HmacSha256Key, HmacSha256Mac},
};

use libcrux_sha2::Algorithm;
use zerocopy::*;

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

pub struct HmacRequest<'a, Scheme> {
    id: ID,
    message: &'a [u8],
    _marker: PhantomData<Scheme>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct HmacResponse<Scheme> {
    signature: [u8; 64],
    _marker: PhantomData<Scheme>,
}

impl<'a, Scheme> SignRequest<'a, Scheme> {
    pub fn new(id: ID, message: &'a [u8]) -> Self {
        Self { id, message, _marker: PhantomData }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_payload(&self) -> &[u8] {
        self.message
    }
}

impl<'a, Scheme> TryFrom<&'a [u8]> for SignRequest<'a, Scheme> {
    type Error = Error;

    fn try_from(request: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, message) = request
            .split_at_checked(crate::ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id: ID = id.try_into().expect("No panic here!");
        Ok(Self { id, message, _marker: PhantomData })
    }
}

impl<'a, Scheme> From<SignRequest<'a, Scheme>> for Vec<u8> {
    fn from(request: SignRequest<Scheme>) -> Self {
        let mut result = request.id.to_vec();
        result.extend(request.message);
        result
    }
}

impl From<EcDsaP256Signature<SHA256>> for SignResponse<EcDsaP256SHA256> {
    fn from(sig: EcDsaP256Signature<SHA256>) -> Self {
        let mut signature = [0u8; 64];
        let signature_components = sig.get_signature();
        let (r, s) = signature_components.as_bytes();
        signature[..32].copy_from_slice(r);
        signature[32..].copy_from_slice(s);
        Self { signature, _marker: PhantomData }
    }
}

impl From<&SignResponse<EcDsaP256SHA256>> for EcDsaP256Signature<SHA256> {
    fn from(sig: &SignResponse<EcDsaP256SHA256>) -> Self {
        let signature = ecdsa::p256::Signature::from_bytes(sig.signature);
        EcDsaP256Signature::<SHA256>::from(signature)
    }
}

impl From<Ed25519Signature> for SignResponse<Ed25519> {
    fn from(sig: Ed25519Signature) -> Self {
        Self { signature: sig.into_bytes(), _marker: PhantomData }
    }
}

impl From<&SignResponse<Ed25519>> for Ed25519Signature {
    fn from(sig: &SignResponse<Ed25519>) -> Self {
        let signature = ed25519::Signature::from_bytes(sig.signature);
        Ed25519Signature::new(signature)
    }
}
