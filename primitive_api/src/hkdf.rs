use std::marker::PhantomData;
use std::sync::MutexGuard;

use libcrux_agent::{agent::Agent, ID};
use libcrux_sha2::SHA256_LENGTH;

use crate::hash::{Hash, Sha2_256};
use crate::{AgentLib, Implementation, Lib, RandomKey};
use crate::provider::{get_agent_and_idx, get_agent_by_idx};

/// HKDF Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Extract,
    Expand,
}

pub struct SharedKeyID {
    id: ID,
    agent_idx: usize,
}

pub trait SaltValue {}

struct AgentSalt {
    id: ID,
    idx: usize,
}

impl SaltValue for AgentSalt {}
impl SaltValue for Vec<u8> {}

pub trait RandomnessExtractor {
    type Salt: SaltValue;

    fn with_salt(&self, salt: Option<Self::Salt>) -> impl SaltedRandomnessExtractor;
}

pub trait SaltedRandomnessExtractor {
    type Key;

    fn extract(&self, key: Option<Self::Key>) -> Result<impl HKDFKey, Error>;
}

/*
pub trait HKDFSource: NetworkObject {
    type Salt: Salt;
    fn extract(key: Option<Self>, salt: Option<&[u8]>) -> Result<impl HKDFKey, Error>;

    fn extract_secret_salt(key: Option<Self>, salt: Option<Self::Salt>) -> Result<impl HKDFKey, Error> {
        unimplemented!()
    }
}*/

pub trait HKDFKey: Send + Sync + Sized {
    fn expand(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error>;
}

struct HKDF<const N: usize, Algo: Hash<N>, Impl: Implementation, Salt: SaltValue>{marker: PhantomData<(Algo, Impl, Salt)>}

struct SaltedHKDF<const N: usize, Algo: Hash<N>, Impl: Implementation, Salt: SaltValue>{
    salt: Option<Salt>,
    marker: PhantomData<(Algo, Impl)>
}
struct HKDFKeyID {
    id: ID,
    agent_idx: usize,
}

fn resolve_agent(
    key: Option<(ID, usize)>,
) -> Result<(MutexGuard<'static, Agent>, usize, Option<ID>), Error> {
    match key {
        None => {
            let (agent, agent_idx) = get_agent_and_idx()
                .ok_or_else(|| Error::Internal("No agent available".into()))?;
            Ok((agent, agent_idx, None))
        }
        Some((id, agent_idx)) => {
            let agent = get_agent_by_idx(agent_idx)
                .ok_or_else(|| Error::Internal("No agent available".into()))?;
            Ok((agent, agent_idx, Some(id)))
        }
    }
}

impl RandomnessExtractor for HKDF<SHA256_LENGTH, Sha2_256, AgentLib, Vec<u8>> {
    type Salt = Vec<u8>;

    fn with_salt(&self, salt: Option<Self::Salt>) -> impl SaltedRandomnessExtractor {
        SaltedHKDF::<SHA256_LENGTH, Sha2_256, AgentLib, Vec<u8>>{salt, marker: PhantomData}
    }
}

impl RandomnessExtractor for HKDF<SHA256_LENGTH, Sha2_256, AgentLib, AgentSalt> {
    type Salt = AgentSalt;

    fn with_salt(&self, salt: Option<Self::Salt>) -> impl SaltedRandomnessExtractor {
        SaltedHKDF::<SHA256_LENGTH, Sha2_256, AgentLib, AgentSalt>{salt, marker: PhantomData}
    }
}

impl SaltedRandomnessExtractor for SaltedHKDF<SHA256_LENGTH, Sha2_256, AgentLib, Vec<u8>> {
    type Key = SharedKeyID;

    fn extract(&self, key: Option<Self::Key>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = key.map(|key| get_agent_by_idx(key.agent_idx).map(|ag| (ag, key.agent_idx, Some(key.id))))
            .unwrap_or(get_agent_and_idx().map(|(ag, idx)| (ag, idx, None)))
            .ok_or(Error::Internal("No Agent".to_string()))?;
        let salt = self.salt.as_deref();
        agent.hkdf_extract_public_salt(id, salt)
            .map(|id| HKDFKeyID{id, agent_idx})
            .map_err(|_| Error::Extract)
    }
}

impl SaltedRandomnessExtractor for SaltedHKDF<SHA256_LENGTH, Sha2_256, AgentLib, AgentSalt> {
    type Key = SharedKeyID;

    fn extract(&self, key: Option<Self::Key>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = key.map(|key| get_agent_by_idx(key.agent_idx).map(|ag| (ag, key.agent_idx, Some(key.id))))
            .unwrap_or(get_agent_and_idx().map(|(ag, idx)| (ag, idx, None)))
            .ok_or(Error::Internal("No Agent".to_string()))?;
        let salt = self.salt.as_deref();
        agent.hkdf_extract_public_salt(id, salt)
            .map(|id| HKDFKeyID{id, agent_idx})
            .map_err(|_| Error::Extract)
    }
}
/*
impl HKDFSource for SharedKeyID {
    type Salt = ID;

    fn extract(key: Option<Self>, salt: Option<&[u8]>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = resolve_agent(key.map(|k| (k.id, k.agent_idx)))?;
        let id = agent.hkdf_extract_public_salt(id, salt).map_err(|_| Error::Extract)?;
        Ok(HKDFKeyID { id, agent_idx })
    }

    fn extract_secret_salt(key: Option<Self>, salt: Option<ID>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = resolve_agent(key.map(|k| (k.id, k.agent_idx)))?;
        let id = agent.hkdf_extract_secret_salt(id, salt).map_err(|_| Error::Extract)?;
        Ok(HKDFKeyID { id, agent_idx })
    }
}

impl TryFrom<&[u8]> for SharedKeyID {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (id, idx) = bytes.split_at_checked(32).map_err()
    }
}*/
impl HKDFKey for HKDFKeyID {
    fn expand(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::Internal("No agent available".into()))?;
        let id = agent.hkdf_expand(self.id.clone(), output_len, info).map_err(|_| Error::Expand)?;
        agent.export_key(id).map_err(|_| Error::Expand)
    }
}

impl SharedKeyID {
    pub fn new(id: ID, agent_idx: usize) -> Self {
        Self { id, agent_idx }
    }

    pub fn id(&self) -> &ID {
        &self.id
    }

    pub fn idx(&self) -> usize {
        self.agent_idx
    }
}

mod test {
    use crate::hkdf::{HKDFSource, SharedKeyID};

    #[test]
    fn test_none_hkdf() {
        let opt = Option::<SharedKeyID>::None;
        (opt as dyn HKDFSource).extract(None)
    }
}