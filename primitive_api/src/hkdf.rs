use std::marker::PhantomData;

use libcrux_agent::hkdf::PseudorandomKey;
use libcrux_agent::kx::SharedKey;
use libcrux_hkdf;
use libcrux_sha2::{Sha256, SHA256_LENGTH};

use crate::provider::get_agent;
use crate::{AgentLib, Implementation, KeyID, Lib, NetworkObject, RandomKey};
use crate::hash::Hash;

/// HKDF Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Extract,
    Expand,
}

pub type DefaultHKDF = Hkdf<SHA256_LENGTH, Sha256, Lib>;

pub trait SaltValue {}
pub trait HkdfIkm {}

impl SaltValue for KeyID<RandomKey> {}
impl SaltValue for RandomKey {}

impl HkdfIkm for KeyID<SharedKey>{}
impl HkdfIkm for SharedKey {}

/// Minimal example:
/// ```
/// use rand::{RngCore, SeedableRng};
/// use rand_chacha::ChaChaRng;
/// 
/// use libcrux_primitive_api::hkdf::*;
/// use libcrux_primitive_api::nike::*;
/// 
/// let (sk_a, pk_a) = DefaultNIKEKey::keygen().expect("Keygen failed");
/// let (sk_b, pk_b) = DefaultNIKEKey::keygen().expect("Keygen failed");
/// 
/// let shk_a = sk_a.derive(pk_b).expect("Derive failed");
/// let shk_b = sk_b.derive(pk_a).expect("Derive failed");
/// 
/// let salt = Some(b"1+1=2".as_ref());
/// let prk_a = DefaultHKDF::new().with_salt(salt).extract_with_key(shk_a).expect("Extraction failed");
/// let prk_b = DefaultHKDF::new().with_salt(salt).extract_with_key(shk_b).expect("Extraction failed");
/// 
/// let info = b"Test key";
/// let okm_a = prk_a.expand(32, info).expect("Expansion failed");
/// let okm_b = prk_b.expand(32, info).expect("Expansion failed");
/// 
/// assert_eq!(okm_a, okm_b)
/// ```
pub trait RandomnessExtractor: Send + Sync {
    type Salt: SaltValue + for <'a> TryFrom<&'a [u8]>;
    type PublicExtractor: SaltedRandomnessExtractor;
    type SecretExtractor: SaltedRandomnessExtractor;

    fn with_salt(&self, salt: Option<&[u8]>) ->  Self::PublicExtractor;

    fn with_secret_salt(&self, salt: Self::Salt) -> Self::SecretExtractor;
}

pub trait SaltedRandomnessExtractor {
    type Key: HkdfIkm + for <'a> TryFrom<&'a [u8]>;
    type Prk: HKDFKey + for <'a> TryFrom<&'a [u8]>;

    fn extract_without_key(self) -> Result<impl HKDFKey, Error>;
    
    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error>;
}

pub trait HKDFKey: Send + Sync {
    const N: usize;
    type Okm: NetworkObject;

    fn expand(&self, output_len: usize, info: &[u8]) -> Result<Self::Okm, Error>;

    fn expand_declassify(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error>;
}

const SHA2_256_SALT: [u8; SHA256_LENGTH] = [0u8; SHA256_LENGTH];

pub struct Hkdf<const N: usize, Algo: Hash<N>, Impl: Implementation>(PhantomData<(Algo, Impl)>);

pub struct Sha256SaltedHKDF<Impl: Implementation>(Vec<u8>, PhantomData<Impl>);
pub struct Sha256SecretSaltedHKDF(KeyID<RandomKey>);

impl<const N: usize, Algo: Hash<N>, Impl: Implementation> Hkdf<N, Algo, Impl> 
{
    pub const fn new() -> Self {
        Self(PhantomData)
    }    
}

impl<const N: usize, Algo: Hash<N>, Impl: Implementation> Default for Hkdf<N, Algo, Impl> {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomnessExtractor for Hkdf<SHA256_LENGTH, Sha256, AgentLib> {
    type Salt = KeyID<RandomKey>;
    type SecretExtractor = Sha256SecretSaltedHKDF;
    type PublicExtractor = Sha256SaltedHKDF<AgentLib>;

    fn with_salt (&self, salt: Option<&[u8]>) ->  Self::PublicExtractor {
        let salt = salt.unwrap_or(&SHA2_256_SALT);
        Sha256SaltedHKDF::<AgentLib>(salt.to_vec(), PhantomData)
    }

    fn with_secret_salt(&self, salt: Self::Salt) -> Self::SecretExtractor {
        Sha256SecretSaltedHKDF(salt)
        
    }
}

impl RandomnessExtractor for Hkdf<SHA256_LENGTH, Sha256, Lib> {
    type Salt = Vec<u8>;
    type SecretExtractor = Sha256SaltedHKDF<Lib>;
    type PublicExtractor = Sha256SaltedHKDF<Lib>;

    fn with_salt (&self, salt: Option<&[u8]>) ->  Self::PublicExtractor {
        let salt = salt.unwrap_or(&SHA2_256_SALT);
        Sha256SaltedHKDF::<Lib>(salt.to_vec(), PhantomData)
    }

    fn with_secret_salt(&self, salt: Self::Salt) -> Self::SecretExtractor {
        Sha256SaltedHKDF::<Lib>(salt, PhantomData)
        
    }
}

impl SaltedRandomnessExtractor for Sha256SaltedHKDF<AgentLib> {
    type Key = KeyID<SharedKey>;
    type Prk = KeyID<Sha256>;

    fn extract_without_key(self) -> Result<impl HKDFKey, Error> {
        let mut prk = [0u8; 32];
        let ikm = [0u8; SHA256_LENGTH];
        libcrux_hkdf::sha2_256::extract(&mut prk, &self.0, &ikm)
            .map(|()| PseudorandomKey::new(prk))
            .map_err(|_| Error::Extract)
    }

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hkdf_extract_public_salt(key.get_id().clone(), &self.0)
            .map(KeyID::<Sha256>::new)
            .map_err(|_| Error::Extract)
    }
}

impl SaltedRandomnessExtractor for Sha256SaltedHKDF<Lib> {
    type Key = SharedKey;
    type Prk = PseudorandomKey;

    fn extract_without_key(self) -> Result<impl HKDFKey, Error> {
        let mut prk = [0u8; 32];
        let ikm = [0u8; SHA256_LENGTH];
        libcrux_hkdf::sha2_256::extract(&mut prk, &self.0, &ikm)
            .map(|()| PseudorandomKey::new(prk))
            .map_err(|_| Error::Extract)
    }

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error> {
        let mut prk = [0u8; 32];
        libcrux_hkdf::sha2_256::extract(&mut prk, &self.0, key.as_ref())
            .map(|()| PseudorandomKey::new(prk))
            .map_err(|_| Error::Extract)
    }
}

impl SaltedRandomnessExtractor for Sha256SecretSaltedHKDF {
    type Key = KeyID<SharedKey>;
    type Prk = KeyID<Sha256>;

    fn extract_without_key(self) -> Result<impl HKDFKey, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hkdf_extract_secret_salt(None, self.0.get_id().clone())
            .map(KeyID::<Sha256>::new)
            .map_err(|_| Error::Extract)
    }

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hkdf_extract_secret_salt(Some(key.get_id().clone()), self.0.get_id().clone())
            .map(KeyID::<Sha256>::new)
            .map_err(|_| Error::Extract)
    }
}
impl HKDFKey for KeyID<Sha256> {
    const N: usize = SHA256_LENGTH;
    type Okm = KeyID<RandomKey>;
    
    fn expand(&self, output_len: usize, info: &[u8]) -> Result<Self::Okm, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hkdf_expand(self.get_id().clone(), output_len, info)
            .map(KeyID::<RandomKey>::new)
            .map_err(|_| Error::Expand)
    }

    fn expand_declassify(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        let agent = get_agent().ok_or_else(|| Error::Internal("No agent available".into()))?;
        agent.hkdf_expand(self.get_id().clone(), output_len, info)
            .map(|id| agent.export_nonce(id).map_err(|_| Error::Expand))
            .map_err(|_| Error::Expand)?
        
    }
}

impl HKDFKey for PseudorandomKey {
    const N: usize = SHA256_LENGTH;
    type Okm = RandomKey;

    fn expand(&self, output_len: usize, info: &[u8]) -> Result<Self::Okm, Error> {
        self.sha2_256_hkdf_expand(info, output_len)
            .map(|okm| okm.into_vec())
            .map_err(|_| Error::Expand)
    }

    fn expand_declassify(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        self.expand(output_len, info)
    }
}