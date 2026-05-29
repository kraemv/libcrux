use std::sync::MutexGuard;

use libcrux_agent::{agent::Agent, ID};

use crate::RandomKey;
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

pub trait Salt {}

impl Salt for ID {}
impl Salt for &[u8] {}

pub trait HKDFSource<T: Salt>: Send + Sync + Sized {
    fn extract(key: Option<Self>, salt: Option<T>) -> Result<impl HKDFKey, Error>;
}

pub trait HKDFKey: Send + Sync + Sized {
    fn expand(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error>;
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

impl HKDFSource<ID> for SharedKeyID {
    fn extract(key: Option<Self>, salt: Option<ID>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = resolve_agent(key.map(|k| (k.id, k.agent_idx)))?;
        let id = agent.hkdf_extract_secret_salt(id, salt).map_err(|_| Error::Extract)?;
        Ok(HKDFKeyID { id, agent_idx })
    }
}

impl HKDFSource<&[u8]> for SharedKeyID {
    fn extract(key: Option<Self>, salt: Option<&[u8]>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = resolve_agent(key.map(|k| (k.id, k.agent_idx)))?;
        let id = agent.hkdf_extract_public_salt(id, salt).map_err(|_| Error::Extract)?;
        Ok(HKDFKeyID { id, agent_idx })
    }
}

impl HKDFSource<ID> for HKDFKeyID {
    fn extract(key: Option<Self>, salt: Option<ID>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = resolve_agent(key.map(|k| (k.id, k.agent_idx)))?;
        let id = agent.hkdf_extract_secret_salt(id, salt).map_err(|_| Error::Extract)?;
        Ok(HKDFKeyID { id, agent_idx })
    }
}

impl HKDFSource<&[u8]> for HKDFKeyID {
    fn extract(key: Option<Self>, salt: Option<&[u8]>) -> Result<impl HKDFKey, Error> {
        let (agent, agent_idx, id) = resolve_agent(key.map(|k| (k.id, k.agent_idx)))?;
        let id = agent.hkdf_extract_public_salt(id, salt).map_err(|_| Error::Extract)?;
        Ok(HKDFKeyID { id, agent_idx })
    }
}

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
