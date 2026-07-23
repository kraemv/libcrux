use std::marker::PhantomData;

use libcrux_agent::hkdf::HkdfSha256PRK;
use libcrux_agent::kx::SharedKey;
use libcrux_hkdf;
use libcrux_sha2::{Sha256, SHA256_LENGTH};
use zeroize::ZeroizeOnDrop;

use crate::aead::AEADKey;
use crate::hash::Hash;
use crate::mac::AuthenticationKey;
use crate::provider::get_agent;
use crate::{AgentLib, Provider, KeyID, Lib, NetworkObject};

/// HKDF Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Conversion,
    Internal(String),
    Expand,
}

pub type DefaultHKDF = Hkdf<SHA256_LENGTH, Sha256, Lib>;

pub trait SaltValue: for<'a> TryFrom<&'a [u8]> {}
pub trait HkdfIkm: ZeroizeOnDrop + for<'a> TryFrom<&'a [u8]> {}

impl SaltValue for KeyID<RandomKey> {}
impl SaltValue for RandomKey {}
impl SaltValue for Vec<u8> {}

impl HkdfIkm for KeyID<SharedKey> {}
impl HkdfIkm for SharedKey {}

pub trait KeyMaterial: ZeroizeOnDrop{
    fn to_aead_key<Algo: AEADKey>(self) -> Result<Algo, Error>;

    fn to_mac_key<Algo: AuthenticationKey>(self) -> Result<Algo, Error>;

    fn to_pseudorandom_key<Algo: HKDFKey>(self) -> Result<Algo, Error>;

    fn to_salt<Algo: SaltValue>(self) -> Result<Algo, Error>;
}

/// Minimal example:
/// ```
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
    type Salt: SaltValue;
    type PublicExtractor: SaltedRandomnessExtractor;
    type SecretExtractor: SaltedRandomnessExtractor;

    fn with_salt(&self, salt: Option<&[u8]>) -> Self::PublicExtractor;

    fn with_secret_salt(&self, salt: Self::Salt) -> Self::SecretExtractor;
}

pub trait SaltedRandomnessExtractor {
    type Key: HkdfIkm;
    type Prk: HKDFKey;

    fn extract_without_key(self) -> Result<impl HKDFKey, Error>;

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error>;
}

pub trait HKDFKey: Send + Sync + for<'a> TryFrom<&'a [u8]> + ZeroizeOnDrop {
    const N: usize;
    type Okm: NetworkObject + KeyMaterial;

    fn expand(&self, output_len: usize, info: &[u8]) -> Result<Self::Okm, Error>;

    fn expand_declassify(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error>;
}

const SHA2_256_SALT: [u8; SHA256_LENGTH] = [0u8; SHA256_LENGTH];

pub struct Hkdf<const N: usize, Alg: Hash<N>, Imp: Provider>(PhantomData<(Alg, Imp)>);

pub struct Sha256SaltedHKDF<Imp: Provider>(Vec<u8>, PhantomData<Imp>);
pub struct Sha256SecretSaltedHKDF(KeyID<RandomKey>);

#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct RandomKey(Vec<u8>);

impl<const N: usize, Alg: Hash<N>, Impl: Provider> Hkdf<N, Alg, Impl> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<const N: usize, Alg: Hash<N>, Imp: Provider> Default for Hkdf<N, Alg, Imp> {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomnessExtractor for Hkdf<SHA256_LENGTH, Sha256, AgentLib> {
    type Salt = KeyID<RandomKey>;
    type SecretExtractor = Sha256SecretSaltedHKDF;
    type PublicExtractor = Sha256SaltedHKDF<AgentLib>;

    fn with_salt(&self, salt: Option<&[u8]>) -> Self::PublicExtractor {
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

    fn with_salt(&self, salt: Option<&[u8]>) -> Self::PublicExtractor {
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
            .map(|()| HkdfSha256PRK::new(prk))
            .map_err(map_hkdf_error)
    }

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hkdf_extract_public_salt(key.get_id().clone(), &self.0)
            .map(KeyID::<Sha256>::new)
            .map_err(map_lib_error)
    }
}

impl SaltedRandomnessExtractor for Sha256SaltedHKDF<Lib> {
    type Key = SharedKey;
    type Prk = HkdfSha256PRK;

    fn extract_without_key(self) -> Result<impl HKDFKey, Error> {
        let mut prk = [0u8; 32];
        let ikm = [0u8; SHA256_LENGTH];
        libcrux_hkdf::sha2_256::extract(&mut prk, &self.0, &ikm)
            .map(|()| HkdfSha256PRK::new(prk))
            .map_err(map_hkdf_error)
    }

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error> {
        let mut prk = [0u8; 32];
        libcrux_hkdf::sha2_256::extract(&mut prk, &self.0, key.as_ref())
            .map(|()| HkdfSha256PRK::new(prk))
            .map_err(map_hkdf_error)
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
            .map_err(map_lib_error)
    }

    fn extract_with_key(self, key: Self::Key) -> Result<Self::Prk, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .hkdf_extract_secret_salt(Some(key.get_id().clone()), self.0.get_id().clone())
            .map(KeyID::<Sha256>::new)
            .map_err(map_lib_error)
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
            .map_err(map_lib_error)
    }

    fn expand_declassify(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        let agent = get_agent().ok_or_else(|| Error::Internal("No agent available".into()))?;
        agent
            .hkdf_expand(self.get_id().clone(), output_len, info)
            .map(|id| agent.export_nonce(id).map_err(map_lib_error))
            .map_err(map_lib_error)?
            .map(RandomKey)
    }
}

impl HKDFKey for HkdfSha256PRK {
    const N: usize = SHA256_LENGTH;
    type Okm = RandomKey;

    fn expand(&self, output_len: usize, info: &[u8]) -> Result<Self::Okm, Error> {
        self.sha2_256_expand(info, output_len)
            .map(|okm| okm.into_vec())
            .map_err(|_| Error::Expand)
            .map(RandomKey)
    }

    fn expand_declassify(&self, output_len: usize, info: &[u8]) -> Result<RandomKey, Error> {
        self.expand(output_len, info)
    }
}

fn map_lib_error(err: libcrux_agent::Error) -> Error {
    match err {
        libcrux_agent::Error::Expand => Error::Expand,
        e => Error::Internal(e.to_string()),
    }
}

fn map_hkdf_error(err: libcrux_hkdf::ExtractError) -> Error {
    match err {
        libcrux_hkdf::ExtractError::ArgumentTooLong => Error::Internal("Input arguments too long".into()),
        libcrux_hkdf::ExtractError::PrkTooShort => Error::Internal("Internal error: Prk too short".into()),
        libcrux_hkdf::ExtractError::Unknown => Error::Internal("Unknown internal error".into()),
    }
}

impl KeyMaterial for KeyID<RandomKey> {
    fn to_aead_key<Algo: AEADKey>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }

    fn to_mac_key<Algo: AuthenticationKey>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }

    fn to_pseudorandom_key<Algo: HKDFKey>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }

    fn to_salt<Algo: SaltValue>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }
}

impl KeyMaterial for RandomKey {
    fn to_aead_key<Algo: AEADKey>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }

    fn to_mac_key<Algo: AuthenticationKey>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }

    fn to_pseudorandom_key<Algo: HKDFKey>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }

    fn to_salt<Algo: SaltValue>(self) -> Result<Algo, Error> {
        Algo::try_from(self.as_ref()).map_err(|_| Error::Conversion)
    }
}

impl NetworkObject for RandomKey{}

impl From<&[u8]> for RandomKey {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl AsRef<[u8]> for RandomKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}