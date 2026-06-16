use std::fmt::Debug;

use crate::provider::get_agent;
use crate::hkdf::HkdfIkm;
use crate::{KeyID, NetworkObject};

use libcrux_agent::kx::{SharedKey, X25519PublicKey, X25519SecretKey};
use libcrux_curve25519 as curve25519;
use libcrux_curve25519::ecdh_api::EcdhOwned;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

/// NIKE Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Derive,
    KeyGen,
    InvalidKey,
    InputTooLarge,
}

pub type DefaultNIKEKey = X25519SecretKey;

pub trait Nike{}

#[derive(Clone, Debug)]
pub struct X25519{}

impl Nike for X25519 {}

/// Minimal example:
/// ```
/// use libcrux_primitive_api::nike::*;
/// 
/// let (sk_a, pk_a) = DefaultNIKEKey::keygen().expect("Keygen failed");
/// let (sk_b, pk_b) = DefaultNIKEKey::keygen().expect("Keygen failed");
/// 
/// let shk_a = sk_a.derive(pk_b).expect("Derive failed");
/// let shk_b = sk_b.derive(pk_a).expect("Derive failed");
/// 
/// assert_eq!(shk_a, shk_b)
/// ```
pub trait NIKESecretKey: Send + Sync + Sized {
    type PublicKey: Debug + NetworkObject;
    type SharedSecret: HkdfIkm + NetworkObject;
    const SCHEME: NIKEScheme;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Derive a shared secret
    fn derive(self, pk: Self::PublicKey) -> Result<Self::SharedSecret, Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum NIKEScheme {
    X25519,
}

impl NIKESecretKey for KeyID<X25519> {
    type PublicKey = X25519PublicKey;
    type SharedSecret = KeyID<SharedKey>;
    const SCHEME: NIKEScheme = NIKEScheme::X25519;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .x25519_generate_key_id()
            .map(|(id, pk)| {(Self::new(id), pk)})
            .map_err(|_| Error::KeyGen)
    }

    fn derive(self, pk: Self::PublicKey) -> Result<KeyID<SharedKey>, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .x25519_derive_for_key_id(self.get_id().clone(), pk)
            .map(KeyID::<SharedKey>::new)
            .map_err(|_| Error::Derive)
    }
}

impl NIKESecretKey for X25519SecretKey {
    type PublicKey = X25519PublicKey;
    type SharedSecret = SharedKey;
    const SCHEME: NIKEScheme = NIKEScheme::X25519;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let mut rng = ChaChaRng::from_os_rng();
        let mut rand = [0u8; 32];
        rng.fill_bytes(&mut rand);
        let (pub_key, priv_key) =
            curve25519::X25519::generate_pair(&rand).map_err(|_| Error::KeyGen)?;

        let key = X25519SecretKey::new(priv_key);
        let pk = X25519PublicKey::new(pub_key);
        Ok((key, pk))
    }

    fn derive(self, pk: Self::PublicKey) -> Result<Self::SharedSecret, Error> {
        X25519SecretKey::derive(&self, &pk).map_err(|_| Error::Derive)
    }
}
impl NetworkObject for X25519PublicKey{}
impl NetworkObject for SharedKey{}