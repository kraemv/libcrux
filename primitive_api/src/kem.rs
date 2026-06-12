use crate::provider::get_agent;
use crate::hkdf::HkdfIkm;

use crate::{KeyID, NetworkObject};

use libcrux_agent::kx::SharedKey;
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
    type SharedSecret: HkdfIkm + NetworkObject;
    const SCHEME: KemScheme;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Decapsulate a key
    fn decaps(&self, ct: Self::Ciphertext) -> Result<Self::SharedSecret, Error>;
}

pub trait EncapsKey: Send + Sync + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {
    type Ciphertext: NetworkObject;
    type SharedSecret: HkdfIkm + NetworkObject;
    const SCHEME: KemScheme;

    // Encapsulate a key and get the encapsulated key
    fn encaps(&self) -> Result<(Self::SharedSecret, Self::Ciphertext), Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum KemScheme {
    MlKem768,
    // X25519MlKem768,
}

impl DecapsKey for KeyID<MlKem768> {
    type PublicKey = MlKem768PublicKey;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = KeyID<SharedKey>;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .mlkem_768_generate_key_id()
            .map(|(id, pk)| {(Self::new(id), pk)})
            .map_err(|_| Error::KeyGen)
    }

    fn decaps(&self, ct:MlKem768Ciphertext ) -> Result<KeyID::<SharedKey>, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .mlkem_768_decaps_for_id(self.get_id().clone(), mlkem768::MlKem768Ciphertext::from(ct))
            .map(KeyID::<SharedKey>::new)
            .map_err(|_| Error::Decaps)
    }
}

impl EncapsKey for MlKem768PublicKey {
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = KeyID<SharedKey>;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn encaps(&self) -> Result<(KeyID::<SharedKey>, MlKem768Ciphertext), Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .mlkem_768_encaps_for_id(self)
            .map(|(id, ct)| (KeyID::<SharedKey>::new(id), ct))
            .map_err(|_| Error::Encaps)
    }
}

impl NetworkObject for MlKem768Ciphertext {}