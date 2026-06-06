use std::marker::PhantomData;

use libcrux_agent::hkdf::PseudorandomKey;
use libcrux_agent::ID;
use libcrux_hkdf;
use libcrux_sha2::SHA256_LENGTH;

use crate::hash::{Hash, Sha2_256};
use crate::{AgentLib, Implementation, RandomKey};
use crate::provider::get_agent_by_idx;

/// HKDF Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Extract,
    Expand,
}

pub trait SaltValue {}
pub trait HkdfIkm {}

pub struct SharedKeyID {
    id: ID,
    agent_idx: usize,
}

impl<const N: usize, Algo: Hash<N>> SaltValue for HKDFKeyID<N, Algo> {}
impl SaltValue for Option<Vec<u8>> {}
impl HkdfIkm for SharedKeyID{}

pub trait RandomnessExtractor: Send + Sync {
    type Salt: SaltValue + for <'a> TryFrom<&'a [u8]>;
    type SecretExtractor: SaltedRandomnessExtractor;

    fn with_salt(&self, salt: Option<&[u8]>) ->  Sha256SaltedHKDF{
        let salt = salt.unwrap_or(&[0u8; SHA256_LENGTH]).to_vec();
        Sha256SaltedHKDF(salt)
    }

    fn with_secret_salt(&self, salt: Self::Salt) -> Self::SecretExtractor;
}

pub trait SaltedRandomnessExtractor {
    type Key: HkdfIkm + for <'a> TryFrom<&'a [u8]>;

    fn extract_without_key(&self) -> Result<impl HKDFKey, Error>;
    
    fn extract_with_key(&self, key: Self::Key) -> Result<impl HKDFKey, Error>;
}

pub trait HKDFKey: Send + Sync + Sized {
    const N: usize;

    fn expand(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error>;
}

pub struct Hkdf<const N: usize, Algo: Hash<N>, Impl: Implementation>{marker: PhantomData<(Algo, Impl)>}

pub struct Sha256SaltedHKDF(Vec<u8>);
pub struct Sha256SecretSaltedHKDF(HKDFKeyID::<SHA256_LENGTH, Sha2_256>);

pub struct HKDFKeyID<const N: usize, Algo: Hash<N>> {
    id: ID,
    agent_idx: usize,
    marker: PhantomData<Algo>,
}

impl RandomnessExtractor for Hkdf<SHA256_LENGTH, Sha2_256, AgentLib> {
    type Salt = HKDFKeyID<SHA256_LENGTH, Sha2_256>;
    type SecretExtractor = Sha256SecretSaltedHKDF;

    fn with_secret_salt(&self, salt: Self::Salt) -> Self::SecretExtractor {
        Sha256SecretSaltedHKDF(salt)
        
    }
}

impl<const N: usize, Algo: Hash<N>, Impl: Implementation> Hkdf<N, Algo, Impl> 
{
    pub const fn new() -> Self {
        Self{marker: PhantomData}
    }    
}

impl<const N: usize, Algo: Hash<N>, Impl: Implementation> Default for Hkdf<N, Algo, Impl> {
    fn default() -> Self {
        Self::new()
    }
}

impl SaltedRandomnessExtractor for Sha256SaltedHKDF {
    type Key = SharedKeyID;

    fn extract_without_key(&self) -> Result<impl HKDFKey, Error> {
        let mut prk = [0u8; 32];
        let ikm = [0u8; SHA256_LENGTH];
        libcrux_hkdf::sha2_256::extract(&mut prk, &self.0, &ikm)
            .map(|()| PseudorandomKey::new(prk))
            .map_err(|_| Error::Extract)
    }

    fn extract_with_key(&self, key: Self::Key) -> Result<impl HKDFKey, Error> {
        let agent = get_agent_by_idx(key.agent_idx)
            .ok_or(Error::Internal("No Agent".to_string()))?;
        agent.hkdf_extract_public_salt(key.id, &self.0)
            .map(|id| HKDFKeyID::<SHA256_LENGTH, Sha2_256>{id, agent_idx: key.agent_idx, marker: PhantomData})
            .map_err(|_| Error::Extract)
    }
}

impl SaltedRandomnessExtractor for Sha256SecretSaltedHKDF {
    type Key = SharedKeyID;

    fn extract_without_key(&self) -> Result<impl HKDFKey, Error> {
        let (salt_id, salt_idx) = (&self.0.id, self.0.agent_idx);
        let agent = get_agent_by_idx(salt_idx)
            .ok_or(Error::Internal("No Agent".to_string()))?;
        agent.hkdf_extract_secret_salt(None, salt_id.clone())
            .map(|id| HKDFKeyID{id, agent_idx: salt_idx, marker: PhantomData})
            .map_err(|_| Error::Extract)
    }

    fn extract_with_key(&self, key: Self::Key) -> Result<impl HKDFKey, Error> {
        let agent = get_agent_by_idx(key.agent_idx)
            .ok_or(Error::Internal("No Agent".to_string()))?;
        agent.hkdf_extract_secret_salt(Some(key.id), self.0.id.clone())
            .map(|id| HKDFKeyID{id, agent_idx: key.agent_idx, marker: PhantomData})
            .map_err(|_| Error::Extract)
    }
}
impl HKDFKey for HKDFKeyID<SHA256_LENGTH, Sha2_256> {
    const N: usize = SHA256_LENGTH;
    
    fn expand(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        let agent = get_agent_by_idx(self.agent_idx)
            .ok_or_else(|| Error::Internal("No agent available".into()))?;
        let id = agent.hkdf_expand(self.id.clone(), output_len, info).map_err(|_| Error::Expand)?;
        agent.export_key(id).map_err(|_| Error::Expand)
    }
}

impl HKDFKey for PseudorandomKey {
    const N: usize = SHA256_LENGTH;

    fn expand(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        self.sha2_256_hkdf_expand(info, output_len)
            .map(|okm| okm.into_vec())
            .map_err(|_| Error::Expand)
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

impl TryFrom<&[u8]> for SharedKeyID {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (id, idx) = value.split_at_checked(size_of::<ID>()).ok_or( Error::Internal("Malformed shared key".to_string()))?;
        let id = ID::try_from(id).map_err(|_| Error::Internal("Malformed ID".to_string()))?;
        let agent_idx = usize::from_be_bytes(idx.try_into().map_err(|_| Error::Internal("Malformed ID".to_string()))?);
        Ok(SharedKeyID { id, agent_idx })
    }
}

impl From<SharedKeyID> for Vec<u8> {

    fn from(shk: SharedKeyID) -> Self {
        let mut id_bytes = shk.id.as_ref().to_vec();
        id_bytes.extend_from_slice(&shk.agent_idx.to_be_bytes());
        id_bytes
    }
}

impl<const N: usize, Algo> TryFrom<&[u8]> for HKDFKeyID<N, Algo> 
where
    Algo: Hash<N>,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (id, idx) = value.split_at_checked(size_of::<ID>()).ok_or( Error::Internal("Malformed shared key".to_string()))?;
        let id = ID::try_from(id).map_err(|_| Error::Internal("Malformed ID".to_string()))?;
        let agent_idx = usize::from_be_bytes(idx.try_into().map_err(|_| Error::Internal("Malformed ID".to_string()))?);
        Ok(HKDFKeyID { id, agent_idx, marker: PhantomData })
    }
}

impl<const N: usize, Algo> From<HKDFKeyID<N, Algo>> for Vec<u8> where
    Algo: Hash<N>,
{

    fn from(key: HKDFKeyID<N, Algo>) -> Self {
        let mut id_bytes = key.id.as_ref().to_vec();
        id_bytes.extend_from_slice(&key.agent_idx.to_be_bytes());
        id_bytes
    }
}