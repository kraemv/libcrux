use std::marker::PhantomData;

use libcrux_agent::{ID, hmac::{HmacSha256Key, HmacSha256Mac, Sha2_256HMAC}};

use crate::{NetworkObject, provider::get_agent_by_idx};

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

pub struct MacKeyId<Scheme> {
    id: ID,
    agent_idx: usize,
    scheme: PhantomData<Scheme>
}

impl AuthenticationKey for MacKeyId<Sha2_256HMAC> {
    type Tag = HmacSha256Mac;

    fn authenticate(&self, msg: &[u8]) -> Result<Self::Tag, Error> {
        let agent = get_agent_by_idx(self.agent_idx).ok_or_else(|| Error::Internal("No agent available".into()))?;
        agent
            .hmac_sha2_256_authenticate(self.id.clone(), msg)
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

impl<Scheme> TryFrom<&[u8]> for MacKeyId<Scheme> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (id, idx) = value.split_at_checked(size_of::<ID>()).ok_or( Error::Internal("Malformed shared key".to_string()))?;
        let id = ID::try_from(id).map_err(|_| Error::Internal("Malformed ID".to_string()))?;
        let agent_idx = usize::from_be_bytes(idx.try_into().map_err(|_| Error::Internal("Malformed ID".to_string()))?);
        Ok(MacKeyId::<Scheme> { id, agent_idx, scheme: PhantomData })
    }
}

impl NetworkObject for HmacSha256Mac {}