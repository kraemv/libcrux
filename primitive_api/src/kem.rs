use std::marker::PhantomData;

use crate::provider::{get_agent_and_idx, get_agent_by_idx};
use crate::hkdf::SharedKeyID;
use crate::hkdf::HKDFSource;

use crate::NetworkObject;

use libcrux_agent::ID;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PublicKey};

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

pub trait Kem{}

#[derive(Clone, Debug)]
pub struct MlKem768{}

impl Kem for MlKem768 {}

pub trait DecapsKey: Send + Sync + Sized {
    type PublicKey: EncapsKey + Sized;
    type Ciphertext: NetworkObject;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Decapsulate a key
    fn decaps(&self, ct: Self::Ciphertext) -> Result<for T:Salt impl HKDFSource<T>, Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> KemScheme;
}

pub trait EncapsKey: Send + Sync + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {
    type Ciphertext: NetworkObject;

    // Encapsulate a key and get the encapsulated key
    fn encaps(&self) -> Result<(impl HKDFSource, Self::Ciphertext), Error>;

    // Get the scheme this key is for
    fn scheme(&self) -> KemScheme;
}

#[derive(Clone, Copy, Debug)]
pub enum KemScheme {
    MlKem768,
    // X25519MlKem768,
}

#[derive(Clone, Debug)]
pub struct DecapsKeyID<Scheme: Kem> {
    id: ID,
    agent_idx: usize,
    scheme: PhantomData<Scheme>
}

impl DecapsKey for DecapsKeyID<MlKem768> {
    type PublicKey = MlKem768PublicKey;
    type Ciphertext = MlKem768Ciphertext;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let (agent, agent_idx) =
            get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
        agent
            .mlkem_768_generate_key_id()
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

    fn decaps(&self, ct:MlKem768Ciphertext ) -> Result<impl HKDFSource, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::Internal("No agent available".into()))?;
        let id = agent
                .mlkem_768_decaps_for_id(self.id.clone(), mlkem768::MlKem768Ciphertext::from(ct))
                .map_err(|_| Error::Decaps)?;
        Ok(SharedKeyID::new(id, self.agent_idx))
    }

    fn scheme(&self) -> KemScheme {
        KemScheme::MlKem768
    }
}

impl EncapsKey for MlKem768PublicKey {
    type Ciphertext = MlKem768Ciphertext;

    fn encaps(&self) -> Result<(impl HKDFSource, MlKem768Ciphertext), Error> {
        let (agent, agent_idx) = get_agent_and_idx().ok_or_else(|| Error::Internal("No agent available".into()))?;
        let (id, ct) = agent
            .mlkem_768_encaps_for_id(self)
            .map_err(|_| Error::Encaps)?;
        Ok((SharedKeyID::new(id, agent_idx), ct))
    }

    fn scheme(&self) -> KemScheme {
        KemScheme::MlKem768
    }
}

impl NetworkObject for MlKem768Ciphertext {}