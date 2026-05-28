use std::marker::PhantomData;

use libcrux_agent::{ID, hmac::{HmacSha256Mac, Sha2_256HMAC}};

use crate::provider::get_agent_by_idx;

pub enum Error {
    Internal(String),
    InvalidTag,
    InvalidKey,
    InputTooLarge,
}

pub enum MacAlgorithm {
    HmacSha2_256,
}

pub trait AuthenticationKey {
    type Tag: Eq;

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