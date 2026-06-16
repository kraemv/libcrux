use libcrux_agent::hmac::{HmacSha256Key, HmacSha256Mac, Sha2_256HMAC};

use crate::{KeyID, NetworkObject, provider::get_agent};

#[derive(Debug)]
pub enum Error {
    Internal(String),
    InvalidTag,
    InvalidKey,
    InputTooLarge,
    Verify,
}

pub enum MacAlgorithm {
    HmacSha2_256,
}

pub type DefaultHmacKey = HmacSha256Key;
/// Minimal example:
/// ```
/// use rand::{RngCore, SeedableRng};
/// use rand_chacha::ChaChaRng;
/// 
/// use libcrux_primitive_api::hmac::*;
/// 
/// let mut rng = ChaChaRng::from_os_rng();
/// let mut key_material = [0u8; 32];
/// rng.fill_bytes(&mut key_material);
/// 
/// let auth_key = DefaultHmacKey::try_from(key_material.as_ref()).expect("Keygen failed");
/// let msg = b"Test message";
/// 
/// let tag = auth_key.authenticate(msg).expect("Authentication failed");
/// let shk_b = match auth_key.verify(msg, tag) {
///     Ok(_) => println!("Valid Tag"),
///     Err(Error::InvalidTag) => println!("Invalid Tag"),
///     Err(Error::Verify) => println!("Verification had an internal error"),
///     _ => println!("Unexpected Error"),
/// };
/// ```
pub trait AuthenticationKey: Send + Sync + for <'a> TryFrom<&'a[u8]>{
    type Tag: Eq + NetworkObject;

    fn authenticate(&self, msg: &[u8]) -> Result<Self::Tag, Error>;

    fn verify(&self, msg: &[u8], tag: Self::Tag) -> Result<(), Error> {
        let new_tag = self.authenticate(msg).map_err(|_| Error::Internal("Agent signing failed".into()))?;
        (new_tag == tag).then_some(()).ok_or(Error::InvalidTag)
    }

    fn scheme() -> MacAlgorithm;
}

impl AuthenticationKey for KeyID<Sha2_256HMAC> {
    type Tag = HmacSha256Mac;

    fn authenticate(&self, msg: &[u8]) -> Result<Self::Tag, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hmac_sha2_256_authenticate(self.get_id().clone(), msg)
            .map_err(|_| Error::Internal("Agent signing failed".into()))
    }

    fn scheme() -> MacAlgorithm {
        MacAlgorithm::HmacSha2_256
    }
}

impl AuthenticationKey for HmacSha256Key {
    type Tag = HmacSha256Mac;

    fn authenticate(&self, msg: &[u8]) -> Result<Self::Tag, Error> {
        Ok(self.authenticate_msg(msg))
    }

    fn scheme() -> MacAlgorithm {
        MacAlgorithm::HmacSha2_256
    }
}

impl NetworkObject for HmacSha256Mac {}