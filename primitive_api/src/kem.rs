use core::fmt::Debug;

use libcrux_curve25519 as curve25519;
use libcrux_ml_kem::mlkem768 as mlkem768;
use crate::provider::get_agent;
use libcrux_agent::{agent::Agent, kx};

/// Signature Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InternalError(String),
    DecapsError,
    EncapsError,
    KeyGenError,
    InvalidKey,
    InputTooLarge,
}

type SharedKey = [u8; 32];

pub trait DecapsKey: Send + Sync + Sized {
    type PublicKey: EncapsKey + Sized;
    const SCHEME: KemScheme = KemScheme::X25519MlKem768;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Decapsulate a key
    fn decaps(self, ct: EncapsulatedKey) -> Result<SharedKey, Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> KemScheme;
}

pub trait EncapsKey: Send + Sync {
    // Encapsulate a key and get the encapsulated key
    fn encaps(self) -> Result<(SharedKey, EncapsulatedKey), Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> KemScheme;
}

#[derive(Clone, Copy, Debug)]
pub enum KemScheme {
    MlKem768,
    X25519,
    X25519MlKem768,
}

pub enum EncapsKeyType {
    MlKem768(mlkem768::MlKem768PublicKey),
    X25519(kx::X25519PublicKey),
    X25519MlKem768(kx::X25519PublicKey, mlkem768::MlKem768PublicKey),
}

pub enum EncapsulatedKey {
    MlKem768(mlkem768::MlKem768Ciphertext),
    X25519(kx::X25519PublicKey),
    X25519MlKem768(kx::X25519PublicKey, mlkem768::MlKem768Ciphertext),
}

pub struct DecapsKeyID {
    id: [u8; 32],
    scheme: KemScheme,
    agent: Agent,
}

impl DecapsKey for DecapsKeyID {
    type PublicKey = EncapsKeyType;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        
    }
}