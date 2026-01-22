//! # Signatures
//!
//! * EcDSA P256 with Sha256, Sha384, and Sha512
//! * EdDSA 25519

use crate::std::vec::Vec;
use core::fmt::Debug;

use crate::hacl::{self, ecdsa, ed25519};
use rand::CryptoRng;

pub use ecdsa::p256::{
    PrivateKey as EcDsaP256PrivateKey, PublicKey as EcDsaP256PublicKey,
    Signature as EcDsaP256Signature,
};

pub use ed25519::{SigningKey as Ed25519PrivateKey, VerificationKey as Ed25519PublicKey};

/// Signature Errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
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
    fn sign(&self, payload: &[u8], rng: &mut impl CryptoRng) -> Result<Signature, Error>;

    // Get the public key belonging to this Signing Key
    fn to_public(&self) -> Result<Self::PublicKey, Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> Algorithm;
}

// A public key to verify a signature
pub trait VerificationKey: Debug + Send + Sync {
    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error>;
    // Get the scheme this key is for
    fn scheme(&self) -> Algorithm;
}

pub enum SigningKeyType {
    EcDsaP256(EcDsaP256PrivKey),
    Ed25519(Ed25519PrivateKey),
}

#[derive(Debug)]
pub enum VerificationKeyType {
    EcDsaP256(EcDsaP256PubKey),
    Ed25519(Ed25519PublicKey),
}

pub struct EcDsaP256PrivKey {
    val: EcDsaP256PrivateKey,
    alg: DigestAlgorithm,
}

#[derive(Debug)]
pub struct EcDsaP256PubKey {
    val: EcDsaP256PublicKey,
    alg: DigestAlgorithm,
}

// A signature that holds its actual value and additional information
pub enum Signature {
    EcDsaP256(EcDsaP256Signature, DigestAlgorithm),
    Ed25519(Ed25519Signature),
}

/// The hash algorithm used for signing or verifying.
pub type DigestAlgorithm = libcrux_sha2::Algorithm;

/// The Signature Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    EcDsaP256(DigestAlgorithm),
    Ed25519,
}

impl EcDsaP256PrivKey {
    pub fn new(val: EcDsaP256PrivateKey, alg: DigestAlgorithm) -> Self {
        Self { val: val, alg: alg }
    }
}

impl EcDsaP256PubKey {
    pub fn new(val: EcDsaP256PublicKey, alg: DigestAlgorithm) -> Self {
        Self { val: val, alg: alg }
    }
}

impl Signature {
    /// Convert the signature into a raw byte vector.
    ///
    /// * NIST P Curve signatures are returned as `r || s`.
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Signature::EcDsaP256(s, _) => {
                let (r, s) = s.as_bytes();
                [r.as_slice(), s.as_slice()].concat()
            }
            Signature::Ed25519(s) => s.signature.to_vec(),
        }
    }
}

impl SigningKey for SigningKeyType {
    type PublicKey = VerificationKeyType;

    fn sign(&self, payload: &[u8], rng: &mut impl CryptoRng) -> Result<Signature, Error> {
        match self {
            SigningKeyType::EcDsaP256(key) => key.sign(payload, rng),
            SigningKeyType::Ed25519(key) => key.sign(payload, rng),
        }
    }

    fn to_public(&self) -> Result<Self::PublicKey, Error> {
        // As generic preferably
        Ok(match self {
            SigningKeyType::EcDsaP256(key) => VerificationKeyType::EcDsaP256(key.to_public()?),
            SigningKeyType::Ed25519(key) => VerificationKeyType::Ed25519(key.to_public()?),
        })
    }

    fn scheme(&self) -> Algorithm {
        match self {
            SigningKeyType::EcDsaP256(key) => key.scheme(),
            SigningKeyType::Ed25519(key) => key.scheme(),
        }
    }
}

impl AsRef<[u8]> for SigningKeyType {
    fn as_ref(&self) -> &[u8] {
        match self {
            SigningKeyType::EcDsaP256(key) => key.val.as_ref(),
            SigningKeyType::Ed25519(key) => key.as_ref(),
        }
    }
}

impl VerificationKey for VerificationKeyType {
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match self {
            VerificationKeyType::EcDsaP256(key) => key.verify(payload, signature),
            VerificationKeyType::Ed25519(key) => key.verify(payload, signature),
        }
    }

    fn scheme(&self) -> Algorithm {
        match self {
            VerificationKeyType::EcDsaP256(key) => key.scheme(),
            VerificationKeyType::Ed25519(key) => key.scheme(),
        }
    }
}

/// A [`Algorithm::Ed25519`] Signature
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature {
    signature: [u8; 64],
}

impl Ed25519Signature {
    /// Generate a signature from the raw 64 bytes.
    pub fn from_bytes(signature: [u8; 64]) -> Self {
        Self { signature }
    }

    /// Generate a signature from the raw bytes slice.
    ///
    /// Returns an error if the slice has legnth != 64.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            signature: bytes.try_into().map_err(|_| Error::InvalidSignature)?,
        })
    }

    /// Get the signature as the raw 64 bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.signature
    }
}

fn into_signing_error(_e: impl Into<hacl::Error>) -> Error {
    Error::SigningError
}

impl SigningKey for EcDsaP256PrivKey {
    type PublicKey = EcDsaP256PubKey;

    // A signing key can sign given a message and extra paramters
    fn sign(&self, payload: &[u8], rng: &mut impl CryptoRng) -> Result<Signature, Error> {
        let nonce = ecdsa::p256::Nonce::random(rng).map_err(|_| Error::SigningError)?;
        let sig_val = ecdsa::p256::sign(self.alg, payload, &self.val, &nonce)
            .map_err(|_| Error::SigningError)?;
        Ok(Signature::EcDsaP256(sig_val, self.alg))
    }

    // Get the public key belonging to this Signing Key
    fn to_public(&self) -> Result<Self::PublicKey, Error> {
        match ecdsa::p256::secret_to_public(&self.val).map_err(|_| Error::KeyGenError) {
            Ok(pk) => Ok(EcDsaP256PubKey {
                val: pk,
                alg: self.alg,
            }),
            Err(e) => Err(e),
        }
    }

    // Get the scheme this key is for
    fn scheme(&self) -> Algorithm {
        Algorithm::EcDsaP256(self.alg)
    }
}

impl SigningKey for Ed25519PrivateKey {
    type PublicKey = Ed25519PublicKey;

    // A signing key can sign given a message and extra paramters
    fn sign(&self, payload: &[u8], _rng: &mut impl CryptoRng) -> Result<Signature, Error> {
        let signature = ed25519::sign(payload, self.as_ref()).map_err(into_signing_error)?;
        Ok(Signature::Ed25519(Ed25519Signature::from_bytes(signature)))
    }

    // Get the public key belonging to this Signing Key
    fn to_public(&self) -> Result<Self::PublicKey, Error> {
        let mut pk = [0u8; 32];
        ed25519::secret_to_public(&mut pk, self.as_ref());
        Ok(ed25519::VerificationKey::from_bytes(pk))
    }

    // Get the scheme this key is for
    fn scheme(&self) -> Algorithm {
        Algorithm::Ed25519
    }
}

impl VerificationKey for EcDsaP256PubKey {
    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match signature {
            Signature::EcDsaP256(sig, alg) => ecdsa::p256::verify(alg, payload, &sig, &self.val)
                .map_err(|_| Error::InvalidSignature),
            _ => Err(Error::InvalidSignature),
        }
    }

    // Get the scheme this key is for
    fn scheme(&self) -> Algorithm {
        Algorithm::EcDsaP256(self.alg)
    }
}

impl VerificationKey for Ed25519PublicKey {
    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Signature) -> Result<(), Error> {
        match signature {
            Signature::Ed25519(sig) => ed25519::verify(payload, self.as_ref(), sig.as_bytes())
                .map_err(|_| Error::InvalidSignature),
            _ => Err(Error::InvalidSignature),
        }
    }

    // Get the scheme this key is for
    fn scheme(&self) -> Algorithm {
        Algorithm::Ed25519
    }
}

/// Generate a fresh key pair.
///
/// The function returns the (secret key, public key) tuple, or an [`Error`].
pub fn key_gen(alg: Algorithm, rng: &mut impl CryptoRng) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match alg {
        Algorithm::EcDsaP256(_) => {
            let sk = EcDsaP256PrivateKey::random(rng).map_err(|_| Error::KeyGenError)?;
            let pk = ecdsa::p256::secret_to_public(&sk).map_err(|_| Error::KeyGenError)?;
            let sk: &[u8] = sk.as_ref();
            let pk: &[u8] = pk.as_ref();
            Ok((sk.to_vec(), pk.to_vec()))
        }
        Algorithm::Ed25519 => {
            let (sk, pk) = ed25519::generate_key_pair(rng).map_err(|_| Error::KeyGenError)?;
            Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec()))
        }
    }
}
