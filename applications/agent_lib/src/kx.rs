use crate::Error;
use libcrux_curve25519::{self as curve25519, ecdh_api::EcdhOwned};
use libcrux_ml_kem::mlkem768;
use rand::CryptoRng;
use zerocopy::*;

pub(crate) struct SharedKey([u8; 32]);

/// An ML-KEM-768 public key (1184 bytes).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
pub struct MlKem768PublicKey([u8; 1184]);

/// An ML-KEM-768 ciphertext (1088 bytes).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
pub struct MlKem768Ciphertext([u8; 1088]);

/// An X25519 public key (32 bytes).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
pub struct X25519PublicKey([u8; 32]);

// TODO: MLKEM PrivateKey

#[derive(PartialEq, Eq)]
#[repr(C)]
pub struct X25519SecretKey([u8; 32]);

impl AsRef<[u8; 32]> for SharedKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SharedKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl MlKem768PublicKey {
    pub fn new(bytes: [u8; 1184]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 1184] {
        &self.0
    }

    pub(crate) fn encaps(&self, rng: &mut impl CryptoRng) -> (MlKem768Ciphertext, SharedKey) {
        let pk = mlkem768::MlKem768PublicKey::from(self.0);
        let mut rand = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut rand);
        let (ct, shk) = mlkem768::encapsulate(&pk, rand);
        (MlKem768Ciphertext::new(ct.into()), SharedKey::new(shk))
    }
}

impl MlKem768Ciphertext {
    pub fn new(bytes: [u8; 1088]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 1088] {
        &self.0
    }
}

impl X25519PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl X25519SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub(crate) fn derive(&self, pk: &X25519PublicKey) -> Result<SharedKey, crate::Error> {
        curve25519::X25519::derive_ecdh(&pk.0, &self.0).map_err(|_| Error::Derive)
            .map(SharedKey)
    }
}

impl From<[u8; 1184]> for MlKem768PublicKey {
    fn from(bytes: [u8; 1184]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 1088]> for MlKem768Ciphertext {
    fn from(bytes: [u8; 1088]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = crate::Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let inner: [u8; 32] = bytes.try_into().map_err(|_| Error::Derive)?;
        Ok(Self(inner))
    }
}

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for MlKem768Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
