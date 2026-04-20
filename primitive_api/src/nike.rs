use crate::provider::{get_agent_and_idx, get_agent_by_idx};
use crate::SharedKey;
use libcrux_agent::kx::{self, X25519PublicKey};

/// Signature Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Derive,
    KeyGen,
    InvalidKey,
    InputTooLarge,
}

pub trait NIKESecretKey: Send + Sync + Sized {
    type PublicKey: NIKEPublicKey + Sized;
    const SCHEME: NIKEScheme;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Derive a shared secret
    fn derive(self, pk: Self::PublicKey) -> Result<SharedKey, Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> NIKEScheme;
}

pub trait NIKEPublicKey: Send + Sync + Sized {
    // Get the scheme this key is for
    fn scheme(&self) -> NIKEScheme;
}

#[derive(Clone, Copy, Debug)]
pub enum NIKEScheme {
    X25519,
}

#[derive(Debug)]
pub enum NIKEPublicKeyType {
    X25519(kx::X25519PublicKey),
}

#[derive(Clone, Debug)]
pub struct NIKESecretKeyID {
    id: [u8; 32],
    scheme: NIKEScheme,
    agent_idx: usize,
}

impl NIKESecretKey for NIKESecretKeyID {
    type PublicKey = NIKEPublicKeyType;
    const SCHEME: NIKEScheme = NIKEScheme::X25519;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
        match Self::SCHEME {
            NIKEScheme::X25519 => agent
                .x25519_generate_key_id()
                .map(|(id, pk)| {
                    (
                        Self {
                            id,
                            scheme: NIKEScheme::X25519,
                            agent_idx,
                        },
                        NIKEPublicKeyType::X25519(pk),
                    )
                })
                .map_err(|_| Error::KeyGen),
        }
    }

    fn derive(self, pk: Self::PublicKey) -> Result<SharedKey, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::Internal("No agent available".into()))?;
        let id = match (pk, self.scheme) {
            (NIKEPublicKeyType::X25519(ct), NIKEScheme::X25519) => agent
                .x25519_derive_for_key_id(self.id, ct)
                .map_err(|_| Error::Derive),
        }?;
        agent.export_key(id).map_err(|_| Error::Derive)
    }

    fn scheme(&self) -> NIKEScheme {
        self.scheme
    }
}

impl NIKEPublicKey for NIKEPublicKeyType {
    fn scheme(&self) -> NIKEScheme {
        match self {
            NIKEPublicKeyType::X25519(_) => NIKEScheme::X25519,
        }
    }
}

impl NIKESecretKeyID {
    pub fn gen_x25519_key() -> Result<(Self, NIKEPublicKeyType), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
        match Self::SCHEME {
            NIKEScheme::X25519 => agent
                .x25519_generate_key_id()
                .map(|(id, pk)| {
                    (
                        Self {
                            id,
                            scheme: NIKEScheme::X25519,
                            agent_idx,
                        },
                        NIKEPublicKeyType::X25519(pk),
                    )
                })
                .map_err(|_| Error::KeyGen),
        }
    }
}

impl NIKEPublicKeyType {
    pub fn new(scheme: NIKEScheme, pk: &[u8]) -> Result<Self, Error> {
        match scheme {
            NIKEScheme::X25519 => pk
                .try_into()
                .map(|pk| {
                    NIKEPublicKeyType::X25519(X25519PublicKey::new(pk))
                })
                .map_err(|_| Error::InputTooLarge),
        }
    }
}

impl NIKEPublicKeyType {
    pub fn to_bytes(&self) -> &[u8] {
        match self {
            NIKEPublicKeyType::X25519(key) => key.as_bytes(),
        }
    }
}
