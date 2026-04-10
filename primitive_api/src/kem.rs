use core::fmt;

use crate::provider::{get_agent, get_agent_and_idx, get_agent_by_idx};
use libcrux_agent::kx::{self, X25519PublicKey};
use libcrux_ml_kem::mlkem768;

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
    const SCHEME: KemScheme;

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
    // X25519MlKem768,
}

pub enum EncapsKeyType {
    MlKem768(Box<mlkem768::MlKem768PublicKey>),
    X25519(kx::X25519PublicKey),
    // X25519MlKem768(kx::X25519PublicKey, mlkem768::MlKem768PublicKey),
}

pub enum EncapsulatedKey {
    MlKem768(Box<mlkem768::MlKem768Ciphertext>),
    X25519(kx::X25519PublicKey),
    // X25519MlKem768(kx::X25519PublicKey, mlkem768::MlKem768Ciphertext),
}

#[derive(Clone, Debug)]
pub struct DecapsKeyID {
    id: [u8; 32],
    scheme: KemScheme,
    agent_idx: usize,
}

impl DecapsKey for DecapsKeyID {
    type PublicKey = EncapsKeyType;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        match Self::SCHEME {
            KemScheme::MlKem768 => agent
                .mlkem_768_generate_key_id()
                .map(|(id, pk)| {
                    (
                        Self {
                            id,
                            scheme: KemScheme::MlKem768,
                            agent_idx,
                        },
                        EncapsKeyType::MlKem768(Box::new(pk)),
                    )
                })
                .map_err(|_| Error::KeyGenError),
            KemScheme::X25519 => agent
                .x25519_generate_key_id()
                .map(|(id, pk)| {
                    (
                        Self {
                            id,
                            scheme: KemScheme::X25519,
                            agent_idx,
                        },
                        EncapsKeyType::X25519(pk),
                    )
                })
                .map_err(|_| Error::KeyGenError),
        }
    }

    fn decaps(self, ct: EncapsulatedKey) -> Result<SharedKey, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::InternalError("No agent available".into()))?;
        let id = match (ct, self.scheme) {
            (EncapsulatedKey::MlKem768(ct), KemScheme::MlKem768) => agent
                .mlkem_768_decaps_for_id(self.id, *ct)
                .map_err(|_| Error::DecapsError),
            (EncapsulatedKey::X25519(ct), KemScheme::X25519) => agent
                .x25519_derive_for_key_id(self.id, ct)
                .map_err(|_| Error::DecapsError),
            _ => Err(Error::InvalidKey),
        }?;
        agent.export_key(id).map_err(|_| Error::DecapsError)
    }

    fn scheme(&self) -> KemScheme {
        self.scheme
    }
}

impl EncapsKey for EncapsKeyType {
    fn encaps(self) -> Result<(SharedKey, EncapsulatedKey), Error> {
        let agent = get_agent().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        let (id, ct) = match self {
            EncapsKeyType::MlKem768(key) => agent
                .mlkem_768_encaps_for_id(*key)
                .map(|(shk, ct)| (shk, EncapsulatedKey::MlKem768(Box::new(ct))))
                .map_err(|_| Error::EncapsError),
            EncapsKeyType::X25519(key) => {
                let (sk, pk) = agent
                    .x25519_generate_key_id()
                    .map_err(|_| Error::EncapsError)?;
                agent
                    .x25519_derive_for_key_id(sk, key)
                    .map(|shk| (shk, EncapsulatedKey::X25519(pk)))
                    .map_err(|_| Error::EncapsError)
            }
        }?;
        agent
            .export_key(id)
            .map(|shk| (shk, ct))
            .map_err(|_| Error::DecapsError)
    }

    fn scheme(&self) -> KemScheme {
        match self {
            EncapsKeyType::MlKem768(_) => KemScheme::MlKem768,
            EncapsKeyType::X25519(_) => KemScheme::X25519,
        }
    }
}

impl DecapsKeyID {
    pub fn gen_mlkem_768_key() -> Result<(Self, EncapsKeyType), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        agent
            .mlkem_768_generate_key_id()
            .map(|(id, pk)| {
                (
                    Self {
                        id,
                        scheme: KemScheme::MlKem768,
                        agent_idx,
                    },
                    EncapsKeyType::MlKem768(Box::new(pk)),
                )
            })
            .map_err(|_| Error::KeyGenError)
    }

    pub fn gen_x25519_key() -> Result<(Self, EncapsKeyType), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        agent
            .x25519_generate_key_id()
            .map(|(id, pk)| {
                (
                    Self {
                        id,
                        scheme: KemScheme::X25519,
                        agent_idx,
                    },
                    EncapsKeyType::X25519(pk),
                )
            })
            .map_err(|_| Error::KeyGenError)
    }
}

impl fmt::Debug for EncapsKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncapsKeyType::MlKem768(key) => {
                f.debug_tuple("MlKem768").field(&key.as_slice()).finish()
            }
            EncapsKeyType::X25519(key) => f.debug_tuple("X25519").field(key).finish(),
        }
    }
}

impl EncapsulatedKey {
    pub fn new(scheme: KemScheme, ct: &[u8]) -> Result<Self, Error> {
        match scheme {
            KemScheme::X25519 => ct
                .try_into()
                .map(|pk: &[u8; 32]| EncapsulatedKey::X25519(X25519PublicKey::new(*pk)))
                .map_err(|_| Error::InputTooLarge),
            KemScheme::MlKem768 => ct
                .try_into()
                .map(|ct: &[u8; 1088]| {
                    EncapsulatedKey::MlKem768(Box::new(mlkem768::MlKem768Ciphertext::from(*ct)))
                })
                .map_err(|_| Error::InputTooLarge),
        }
    }
}

impl EncapsKeyType {
    pub fn to_bytes(&self) -> &[u8] {
        match self {
            EncapsKeyType::MlKem768(key) => key.as_slice(),
            EncapsKeyType::X25519(key) => key.as_bytes(),
        }
    }
}
