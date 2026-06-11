use libcrux_agent::hmac::{HmacSha256Key, HmacSha256Mac, Sha2_256HMAC};

use crate::{KeyID, NetworkObject, provider::get_agent_by_idx};

#[derive(Debug)]
pub enum Error {
    Internal(String),
    InvalidTag,
    InvalidKey,
    InputTooLarge,
}

pub enum MacAlgorithm {
    HmacSha2_256,
}

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
        let agent = get_agent_by_idx(self.get_idx()).ok_or_else(|| Error::Internal("No agent available".into()))?;
        agent
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
        Ok(self.authenticate(msg))
    }

    fn scheme() -> MacAlgorithm {
        MacAlgorithm::HmacSha2_256
    }
}

impl NetworkObject for HmacSha256Mac {}