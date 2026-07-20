use std::marker::PhantomData;

use crate::hkdf::HkdfIkm;
use crate::provider::get_agent;

use crate::{AgentLib, Implementation, KeyID, Lib, NetworkObject};

use libcrux_agent::kx::SharedKey;
use libcrux_ml_kem;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey};

use libcrux_hmac_drbg::HmacDrbgSha256;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::{Rng, SeedableRng};
use zeroize::ZeroizeOnDrop;

/// KEM Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Internal(String),
    Rejected,
}

pub type DefaultKEMKey = MlKem768PrivateKey;

pub trait Kem {}

#[derive(Clone, Debug)]
pub struct MlKem768 {}

impl Kem for MlKem768 {}

/// Minimal example:
/// ```
/// use libcrux_primitive_api::kem::*;
///
/// let (sk_a, pk_a) = DefaultKEMKey::keygen().expect("Keygen failed");
///
/// let (shk_a, ct) = pk_a.encaps().expect("Encaps failed");
/// let shk_b = match sk_a.decaps(ct) {
///     Ok(shk_b) => shk_b,
///     Err(Error::Rejected) => return println!("Rejected ciphertext"),
///     Err(Error::Internal(s)) => return println!("{}", s),
///     _ => return println!("Unexpected Error"),
/// };
///
/// assert_eq!(shk_a, shk_b)
/// ```
pub trait DecapsKey: Send + Sync + Sized + ZeroizeOnDrop {
    type PublicKey: EncapsKey;
    type Ciphertext: NetworkObject;
    type SharedSecret: HkdfIkm + NetworkObject;
    const SCHEME: KemScheme;

    // Generate a private-public key pair
    fn keygen() -> Result<(Self, Self::PublicKey), Error>;

    // Decapsulate a key
    fn decaps(self, ct: Self::Ciphertext) -> Result<Self::SharedSecret, Error>;
}

pub trait EncapsKey: NetworkObject + Sized {
    type Ciphertext: NetworkObject;
    type SharedSecret: HkdfIkm + NetworkObject;
    const SCHEME: KemScheme;

    // Encapsulate a key and get the encapsulated key
    fn encaps(self) -> Result<(Self::SharedSecret, Self::Ciphertext), Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum KemScheme {
    MlKem768,
    // X25519MlKem768,
}

pub struct MlKem768PublicKey<Impl: Implementation> {
    inner: mlkem768::MlKem768PublicKey,
    marker: PhantomData<Impl>,
}

impl<Impl: Implementation> MlKem768PublicKey<Impl> {
    fn new(pk: mlkem768::MlKem768PublicKey) -> Self {
        Self {
            inner: pk,
            marker: PhantomData,
        }
    }
}

impl DecapsKey for KeyID<MlKem768> {
    type PublicKey = MlKem768PublicKey<AgentLib>;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = KeyID<SharedKey>;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .mlkem_768_generate_key_id()
            .map(|(id, pk)| (Self::new(id), MlKem768PublicKey::new(pk)))
            .map_err(|err| Error::Internal(err.to_string()))
    }

    fn decaps(self, ct: MlKem768Ciphertext) -> Result<KeyID<SharedKey>, Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .mlkem_768_decaps_for_id(self.get_id().clone(), MlKem768Ciphertext::from(ct))
            .map(KeyID::<SharedKey>::new)
            .map_err(|e| Error::Internal(e.to_string()))
    }
}

impl EncapsKey for MlKem768PublicKey<AgentLib> {
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = KeyID<SharedKey>;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn encaps(self) -> Result<(KeyID<SharedKey>, MlKem768Ciphertext), Error> {
        get_agent()
            .ok_or_else(|| Error::Internal("No agent available".into()))?
            .mlkem_768_encaps_for_id(&self.inner)
            .map(|(id, ct)| (KeyID::<SharedKey>::new(id), ct))
            .map_err(|err| Error::Internal(err.to_string()))
    }
}

impl DecapsKey for MlKem768PrivateKey {
    type PublicKey = MlKem768PublicKey<Lib>;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = SharedKey;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let mut rng = UnwrapErr(
            HmacDrbgSha256::try_from_rng(&mut SysRng)
                .map_err(|_| Error::Internal("RNG init failed".into()))?,
        );
        let mut rand = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut rand);
        let (sk, pk) = mlkem768::generate_key_pair(rand).into_parts();
        Ok((sk, MlKem768PublicKey::new(pk)))
    }

    fn decaps(self, ct: MlKem768Ciphertext) -> Result<SharedKey, Error> {
        Ok(SharedKey::new(mlkem768::decapsulate(&self, &ct)))
    }
}

impl EncapsKey for MlKem768PublicKey<Lib> {
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = SharedKey;
    const SCHEME: KemScheme = KemScheme::MlKem768;

    fn encaps(self) -> Result<(SharedKey, MlKem768Ciphertext), Error> {
        let mut rng = UnwrapErr(
            HmacDrbgSha256::try_from_rng(&mut SysRng)
                .map_err(|_| Error::Internal("RNG init failed".into()))?,
        );
        let mut rand = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut rand);
        let (ct, shk) = mlkem768::encapsulate(&self.inner, rand);
        Ok((SharedKey::new(shk), ct))
    }
}

impl NetworkObject for MlKem768Ciphertext {}
impl<Impl: Implementation + Send + Sync> NetworkObject for MlKem768PublicKey<Impl> {}

impl<Impl: Implementation> AsRef<[u8]> for MlKem768PublicKey<Impl> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<Impl: Implementation> TryFrom<&[u8]> for MlKem768PublicKey<Impl> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        mlkem768::MlKem768PublicKey::try_from(value)
            .map(|pk| Self::new(pk))
            .map_err(|_| Error::Internal("Invalid public key".into()))
    }
}
