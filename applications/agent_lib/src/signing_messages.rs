use std::marker::PhantomData;

use crate::{
    Error, ID, ID_SIZE,
    signatures::{
        EcDsaP256PrivateKey, EcDsaP256PublicKey, EcDsaP256SHA256, EcDsaP256Signature,
        Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, SHA256,
    },
};

use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_sha2::Algorithm;
use zerocopy::*;

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
enum DigestAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

pub struct SignRequest<'a, Scheme> {
    id: ID,
    message: &'a [u8],
    _marker: PhantomData<Scheme>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct SignResponse<Scheme> {
    signature: [u8; 64],
    _marker: PhantomData<Scheme>,
}

impl From<Algorithm> for DigestAlgorithm {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::Sha224 => DigestAlgorithm::Sha224,
            Algorithm::Sha256 => DigestAlgorithm::Sha256,
            Algorithm::Sha384 => DigestAlgorithm::Sha384,
            Algorithm::Sha512 => DigestAlgorithm::Sha512,
        }
    }
}

impl From<DigestAlgorithm> for Algorithm {
    fn from(alg: DigestAlgorithm) -> Self {
        match alg {
            DigestAlgorithm::Sha224 => Algorithm::Sha224,
            DigestAlgorithm::Sha256 => Algorithm::Sha256,
            DigestAlgorithm::Sha384 => Algorithm::Sha384,
            DigestAlgorithm::Sha512 => Algorithm::Sha512,
        }
    }
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
        let mut result = request.id.0.to_vec();
        result.extend(request.message);
        result
    }
}

impl From<EcDsaP256Signature<SHA256>> for SignResponse<EcDsaP256SHA256> {
    fn from(sig: EcDsaP256Signature<SHA256>) -> Self {
        let signature = *sig.get_signature().as_bytes();
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

// ---------------------------------------------------------------------------
// Key setup
// ---------------------------------------------------------------------------

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum InitResult {
    Success,
    Failure,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct SetupRequest<Scheme> {
    sk: [u8; 32],
    _marker: PhantomData<Scheme>,
}

pub struct SetupResponse<PublicKey> {
    id: ID,
    pk: PublicKey,
}

impl<PublicKey> SetupResponse<PublicKey> {
    pub fn get_id(&self) -> &ID {
        &self.id
    }
}

impl SetupResponse<EcDsaP256PublicKey<SHA256>> {
    pub fn new(id: ID, pk: EcDsaP256PublicKey<SHA256>) -> Self {
        Self { id, pk }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.id.0.to_vec();
        res.extend_from_slice(&self.pk.get_key().0);
        res
    }
}

impl SetupResponse<Ed25519PublicKey> {
    pub fn new(id: ID, pk: Ed25519PublicKey) -> Self {
        Self { id, pk }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.id.0.to_vec();
        res.extend_from_slice(self.pk.as_bytes());
        res
    }
}

impl TryFrom<&[u8]> for SetupResponse<EcDsaP256PublicKey<SHA256>> {
    type Error = Error;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        let (id, pk) = payload
            .split_at_checked(ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id = ID::try_from(id).map_err(|_| Error::MalformedRequest)?;
        let pk: [u8; 64] = pk.try_into().map_err(|_| Error::MalformedRequest)?;
        let pk = EcDsaP256PublicKey::<SHA256>::from(ecdsa::p256::PublicKey(pk));
        Ok(Self { id, pk })
    }
}

impl TryFrom<&[u8]> for SetupResponse<Ed25519PublicKey> {
    type Error = Error;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        let (id, pk) = payload
            .split_at_checked(ID_SIZE)
            .ok_or(Error::MalformedRequest)?;
        let id = ID::try_from(id).map_err(|_| Error::MalformedRequest)?;
        let pk: [u8; 32] = pk.try_into().map_err(|_| Error::MalformedRequest)?;
        let pk = Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(pk));
        Ok(Self { id, pk })
    }
}

impl From<SetupResponse<EcDsaP256PublicKey<SHA256>>> for EcDsaP256PublicKey<SHA256> {
    fn from(response: SetupResponse<EcDsaP256PublicKey<SHA256>>) -> Self {
        response.pk.clone()
    }
}

impl From<SetupResponse<Ed25519PublicKey>> for Ed25519PublicKey {
    fn from(response: SetupResponse<Ed25519PublicKey>) -> Self {
        Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(*response.get_id().as_ref()))
    }
}

impl SetupRequest<EcDsaP256SHA256> {
    pub fn get_private_key(&self) -> Result<EcDsaP256PrivateKey<SHA256>, Error> {
        let sk = libcrux_ecdsa::p256::PrivateKey::try_from(&self.sk)
            .map_err(|_| Error::MalformedRequest)?;
        Ok(EcDsaP256PrivateKey::from(sk))
    }
}

impl SetupRequest<Ed25519> {
    pub fn get_private_key(&self) -> Ed25519PrivateKey {
        let sk = libcrux_ed25519::SigningKey::from_bytes(self.sk);
        Ed25519PrivateKey::new(sk)
    }
}

impl From<&EcDsaP256PrivateKey<SHA256>> for SetupRequest<EcDsaP256SHA256> {
    fn from(key: &EcDsaP256PrivateKey<SHA256>) -> Self {
        Self { sk: *key.as_bytes(), _marker: PhantomData }
    }
}

impl From<&Ed25519PrivateKey> for SetupRequest<Ed25519> {
    fn from(key: &Ed25519PrivateKey) -> Self {
        Self { sk: *key.as_bytes(), _marker: PhantomData }
    }
}

impl From<Result<(), Error>> for InitResult {
    fn from(res: Result<(), Error>) -> Self {
        match res {
            Ok(()) => InitResult::Success,
            Err(_) => InitResult::Failure,
        }
    }
}
