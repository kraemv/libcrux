use core::fmt;

use crate::provider::{get_agent_and_idx, get_agent_by_idx};
use crate::hkdf::SharedKey;
use libcrux_agent::ID;
use libcrux_ml_kem::mlkem768;

/// KEM Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Decaps,
    Encaps,
    KeyGen,
    InvalidKey,
    InputTooLarge,
}

pub trait DecapsKey: Send + Sync + Sized {
    type PublicKey: EncapsKey + Sized;
    const SCHEME: KemScheme;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Decapsulate a key
    fn decaps(&self, ct: EncapsulatedKey) -> Result<SharedKey, Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> KemScheme;
}

pub trait EncapsKey: Send + Sync {
    // Encapsulate a key and get the encapsulated key
    fn encaps(&self) -> Result<(SharedKey, EncapsulatedKey), Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> KemScheme;
}

#[derive(Clone, Copy, Debug)]
pub enum KemScheme {
    MlKem768,
    // X25519MlKem768,
}

pub enum EncapsKeyType {
    MlKem768(Box<mlkem768::MlKem768PublicKey>),
    // X25519MlKem768(kx::X25519PublicKey, mlkem768::MlKem768PublicKey),
}

pub enum EncapsulatedKey {
    MlKem768(Box<mlkem768::MlKem768Ciphertext>),
    // X25519MlKem768(kx::X25519PublicKey, mlkem768::MlKem768Ciphertext),
}

#[derive(Clone, Debug)]
pub struct DecapsKeyID {
    id: ID,
    scheme: KemScheme,
    agent_idx: usize,
}

impl DecapsKey for DecapsKeyID {
    type PublicKey = EncapsKeyType;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
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
                .map_err(|_| Error::KeyGen),
        }
    }

    fn decaps(&self, ct: EncapsulatedKey) -> Result<SharedKey, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::Internal("No agent available".into()))?;
        let id = match (ct, self.scheme) {
            (EncapsulatedKey::MlKem768(ct), KemScheme::MlKem768) => agent
                .mlkem_768_decaps_for_id(self.id.clone(), *ct)
                .map_err(|_| Error::Decaps),
        }?;
        Ok(SharedKey::new(id, self.agent_idx))
    }

    fn scheme(&self) -> KemScheme {
        self.scheme
    }
}

impl EncapsKey for EncapsKeyType {
    fn encaps(&self) -> Result<(SharedKey, EncapsulatedKey), Error> {
        let (agent, agent_idx) = get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
        let (id, ct) = match self {
            EncapsKeyType::MlKem768(key) => agent
                .mlkem_768_encaps_for_id(key)
                .map(|(shk, ct)| (shk, EncapsulatedKey::MlKem768(Box::new(ct))))
                .map_err(|_| Error::Encaps),
        }?;
        Ok((SharedKey::new(id, agent_idx), ct))
    }

    fn scheme(&self) -> KemScheme {
        match self {
            EncapsKeyType::MlKem768(_) => KemScheme::MlKem768,
        }
    }
}

impl DecapsKeyID {
    pub fn gen_mlkem_768_key() -> Result<(Self, EncapsKeyType), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
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
            .map_err(|_| Error::KeyGen)
    }
}

impl fmt::Debug for EncapsKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncapsKeyType::MlKem768(key) => {
                f.debug_tuple("MlKem768").field(&key.as_slice()).finish()
            }
        }
    }
}

impl EncapsulatedKey {
    pub fn new(scheme: KemScheme, ct: &[u8]) -> Result<Self, Error> {
        match scheme {
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
        }
    }
}
