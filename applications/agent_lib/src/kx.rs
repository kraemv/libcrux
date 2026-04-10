use zerocopy::*;
use libcrux_curve25519::{self as curve25519, ecdh_api::EcdhOwned};
use crate::Error;

/// An ML-KEM-768 public key (1184 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768PublicKey([u8; 1184]);

/// An ML-KEM-768 ciphertext (1088 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768Ciphertext([u8; 1088]);

/// An X25519 public key (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct X25519PublicKey([u8; 32]);

#[derive(PartialEq, Eq)]
#[repr(C)]
pub struct X25519SecretKey([u8; 32]);

impl MlKem768PublicKey {
    pub fn new(bytes: [u8; 1184]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 1184] { &self.0 }
}

impl MlKem768Ciphertext {
    pub fn new(bytes: [u8; 1088]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 1088] { &self.0 }
}

impl X25519PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

impl X25519SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn derive(&self, pk: &X25519PublicKey) -> Result<[u8; 32], crate::Error> {
        curve25519::X25519::derive_ecdh(&pk.0, &self.0)
            .map_err(|_| Error::Derive)
    }
}

impl From<[u8; 1184]> for MlKem768PublicKey {
    fn from(bytes: [u8; 1184]) -> Self { Self(bytes) }
}

impl From<[u8; 1088]> for MlKem768Ciphertext {
    fn from(bytes: [u8; 1088]) -> Self { Self(bytes) }
}

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self { Self(bytes) }
}

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8]> for MlKem768Ciphertext {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}