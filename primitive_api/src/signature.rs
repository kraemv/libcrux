//! # Signatures
//!
//! * EcDSA P256 with Sha256, Sha384, and Sha512
//! * EdDSA 25519

use core::fmt::Debug;

use crate::provider::get_agent;
use libcrux_agent::signatures;
use libcrux_ecdsa as ecdsa;
use libcrux_ecdsa::DigestAlgorithm;
use libcrux_ed25519 as ed25519;

/// Signature Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InternalError(String),
    SigningError,
    InvalidSignature,
    KeyGenError,
    InvalidKey,
    InputTooLarge,
}

// A private key that can be used to craft a signature
pub trait SigningKey: Send + Sync {
    type PublicKey: VerificationKey;

    // A signing key can sign given a message, extra parameters and a randomness source
    fn sign(&self, payload: &[u8]) -> Result<Signature, Error>;

    // Get the public key belonging to this Signing Key
    fn to_public(&self) -> &Self::PublicKey;

    // Get the scheme this key is for
    fn scheme(&self) -> SignatureScheme;
}

// A public key to verify a signature
pub trait VerificationKey: Debug + Send + Sync {
    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> SignatureScheme;
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
    id: [u8; 32],
    scheme: SignatureScheme,
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
    pub fn new(id: [u8; 32], scheme: SignatureScheme, public_key: VerificationKeyType) -> Self {
        Self { id, scheme, public_key }
    }
}

impl SigningKey for SigningKeyID {
    type PublicKey = VerificationKeyType;

    fn sign(&self, payload: &[u8]) -> Result<Signature, Error> {
        let agent = get_agent().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        match self.scheme {
            SignatureScheme::EcDsaP256(DigestAlgorithm::Sha256) => agent
                .sign_for_ecdsa_p256_id(self.id, payload.to_vec())
                .map(Signature::EcDsaP256),
            SignatureScheme::Ed25519 => agent
                .sign_for_ed25519_id(self.id, payload.to_vec())
                .map(Signature::Ed25519),
            _ => return Err(Error::InvalidKey),
        }
        .map_err(|_| Error::InternalError("Agent signing failed".into()))
    }

    fn to_public(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl VerificationKey for VerificationKeyType {
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match self {
            VerificationKeyType::EcDsaP256(key) => key.verify(payload, signature),
            VerificationKeyType::Ed25519(key) => key.verify(payload, signature),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match self {
            VerificationKeyType::EcDsaP256(key) => key.scheme(),
            VerificationKeyType::Ed25519(key) => key.scheme(),
        }
    }
}

impl AsRef<[u8]> for VerificationKeyType {
    fn as_ref(&self) -> &[u8] {
        match self {
            VerificationKeyType::EcDsaP256(key) => key.get_key().as_ref(),
            VerificationKeyType::Ed25519(key) => key.as_bytes(),
        }
    }
}

impl VerificationKey for signatures::EcDsaP256PublicKey {
    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match signature {
            Signature::EcDsaP256(sig) => {
                ecdsa::p256::verify(sig.get_alg(), payload, &sig.get_signature(), self.get_key())
                    .map_err(|_| Error::InvalidSignature)
            }
            _ => Err(Error::InvalidSignature),
        }
    }

    // Get the scheme this key is for
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::EcDsaP256(self.get_alg())
    }
}

impl VerificationKey for signatures::Ed25519PublicKey {
    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match signature {
            Signature::Ed25519(sig) => {
                ed25519::verify(payload, &self.into_bytes(), sig.get_signature())
                    .map_err(|_| Error::InvalidSignature)
            }
            _ => Err(Error::InvalidSignature),
        }
    }

    // Get the scheme this key is for
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}
