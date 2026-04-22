//! # Signatures
//!
//! * EcDSA P256 with Sha256, Sha384, and Sha512
//! * EdDSA 25519

use core::fmt::Debug;

use crate::provider::get_agent;
use libcrux_agent::signatures::{EcDsaP256Signature, Ed25519Signature};
use libcrux_agent::{signatures, ID};
use libcrux_ecdsa as ecdsa;
use libcrux_ecdsa::DigestAlgorithm;
use libcrux_ed25519 as ed25519;

pub type DefaultSigningKey = libcrux_ed25519::SigningKey;

/// Signature Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InternalError(String),
    SigningError,
    InvalidSignature,
    KeyGenError,
    InvalidKey,
    InputTooLarge,
    Verify
}
pub trait Sig {}
pub struct Ed25519{}
pub struct EcDsaP256{}

impl Sig for Ed25519 {}
impl Sig for EcDsaP256 {}

/// Minimal example:
/// ```
/// use libcrux_primitive_api::signature::*;
/// 
/// let (sk, vk) = DefaultSigningKey::keygen().expect("Keygen failed");
/// 
/// let msg = b"Test message";
/// let sig = sk.sign(msg).expect("Signing failed");
/// 
/// match vk.verify(msg, sig) {
///     Ok(_) => println!("Valid signature"),
///     Err(Error::InvalidSignature) => println!("Invalid signature"),
///     Err(Error::Verify) => println!("Verification had an internal error"),
///     _ => println!("Unexpected Error"),
/// }
/// ```
/// Missing: signing key from file
/// Missing: Verification for existing signature
/// 
/// Marker traits: implement markers to specify security notions, robustness properties...
/// 
/// To document (via Marker traits):
/// Minimum bits of security
/// Security notions like EUF SUF
/// 
/// Length requirements for variable length input/output schemes
/// 
/// In future: Default is PQ
pub trait SigningKey<Scheme: Sig = Ed25519>: Send + Sync + Sized {
    type PublicKey: VerificationKey + Sized;
    // const SCHEME: SignatureScheme;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        todo!()
    }

    // A signing key can sign given a message, extra parameters and a randomness source
    fn sign(&self, payload: &[u8]) -> Result<Signature, Error>;

    // Get the public key belonging to this Signing Key
    fn to_public(&self) -> &Self::PublicKey;
}

// A public key to verify a signature
pub trait VerificationKey<Scheme: Sig = Ed25519>: Debug + Send + Sync {
    type VerificationError: Debug;
    type Signature;

    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Self::VerificationError>;
}

#[derive(Clone, Copy, Debug)]
pub enum SignatureScheme {
    EcDsaP256(DigestAlgorithm),
    Ed25519,
}

#[derive(Clone, Debug)]
pub enum VerificationKeyType {
    EcDsaP256(signatures::EcDsaP256PublicKey),
    Ed25519(signatures::Ed25519PublicKey),
}

// A signature that holds its actual value and additional information
pub enum Signature {
    EcDsaP256(signatures::EcDsaP256Signature),
    Ed25519(signatures::Ed25519Signature),
}

#[derive(Clone, Debug)]
pub struct SigningKeyID {
    id: ID,
    public_key: VerificationKeyType,
}

impl Signature {
    /// Convert the signature into a raw byte vector.
    ///
    /// * NIST P Curve signatures are returned as `r || s`.
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Signature::EcDsaP256(s) => {
                let signature = s.get_signature();
                let (r, s) = signature.as_bytes();
                [r, s.as_slice()].concat()
            }
            Signature::Ed25519(s) => s.as_bytes().to_vec(),
        }
    }
}

impl SigningKeyID {
    pub fn new(id: ID, public_key: VerificationKeyType) -> Self {
        Self {
            id,
            public_key,
        }
    }
}

/*impl SigningKey<Ed25519> for SigningKeyID {
    type PublicKey = VerificationKeyType;

    fn sign(&self, payload: &[u8]) -> Result<Signature, Error> {
        let agent = get_agent().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        agent
            .ed25519_sign_for_id(self.id, payload.to_vec())
            .map(Signature::Ed25519)
            .map_err(|_| Error::InternalError("Agent signing failed".into()))
    }

    fn to_public(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

impl SigningKey<EcDsaP256> for SigningKeyID {
    type PublicKey = VerificationKeyType;

    fn sign(&self, payload: &[u8]) -> Result<Signature, Error> {
        let agent = get_agent().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        agent
            .ecdsa_p256_sign_for_id(self.id, payload.to_vec())
            .map(Signature::EcDsaP256)
            .map_err(|_| Error::InternalError("Agent signing failed".into()))
    }

    fn to_public(&self) -> &Self::PublicKey {
        &self.public_key
    }
}*/

/*
impl VerificationKey for VerificationKeyType {
    type VerificationError = Error;


    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match self {
            VerificationKeyType::EcDsaP256(key) => todo!(),//key.verify(payload, signature),
            VerificationKeyType::Ed25519(key) => key.verify(payload, signature),
        }
    }
}*/

impl AsRef<[u8]> for VerificationKeyType {
    fn as_ref(&self) -> &[u8] {
        match self {
            VerificationKeyType::EcDsaP256(key) => key.get_key().as_ref(),
            VerificationKeyType::Ed25519(key) => key.as_bytes(),
        }
    }
}
