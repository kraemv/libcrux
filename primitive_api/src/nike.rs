use std::marker::PhantomData;
use std::fmt::Debug;

use crate::provider::{get_agent_and_idx, get_agent_by_idx};
use crate::hkdf::{HkdfIkm, SharedKeyID};
use crate::NetworkObject;
use libcrux_agent::ID;
use libcrux_agent::kx::X25519PublicKey;

/// NIKE Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Derive,
    KeyGen,
    InvalidKey,
    InputTooLarge,
}

pub trait Nike{}

#[derive(Clone, Debug)]
pub struct X25519{}

impl Nike for X25519 {}


pub trait NIKESecretKey: Send + Sync + Sized {
    type PublicKey: Debug + NetworkObject;
    type SharedSecret: HkdfIkm + Into<Vec<u8>>;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Derive a shared secret
    fn derive(self, pk: Self::PublicKey) -> Result<Self::SharedSecret, Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> NIKEScheme;
}

#[derive(Clone, Copy, Debug)]
pub enum NIKEScheme {
    X25519,
}

#[derive(Clone, Debug)]
pub struct NIKESecretKeyID<Scheme: Nike> {
    id: ID,
    agent_idx: usize,
    scheme: PhantomData<Scheme>,
}

impl NIKESecretKey for NIKESecretKeyID<X25519> {
    type PublicKey = X25519PublicKey;
    type SharedSecret = SharedKeyID;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
        agent
            .x25519_generate_key_id()
            .map(|(id, pk)| {
                (
                    Self {
                        id,
                        agent_idx,
                        scheme: PhantomData,
                    },
                    pk,
                )
            })
            .map_err(|_| Error::KeyGen)
    }

    fn derive(self, pk: Self::PublicKey) -> Result<SharedKeyID, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::Internal("No agent available".into()))?;
        let id = agent
                .x25519_derive_for_key_id(self.id, pk)
                .map_err(|_| Error::Derive)?;
        Ok(SharedKeyID::new(id, self.agent_idx))
    }

    fn scheme(&self) -> NIKEScheme {
        NIKEScheme::X25519
    }
}

impl NetworkObject for X25519PublicKey{}