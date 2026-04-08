use libcrux_ml_kem::mlkem768::MlKem768PublicKey;
use zerocopy::*;
use crate::{kx::{self, X25519PublicKey}};
use crate::ID;

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct X25519DeriveRequest{
    id: ID,
    key: kx::X25519PublicKey,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768DecapsRequest{
    id: ID,
    ct: kx::MlKem768Ciphertext,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768EncapsRequest{
    key: kx::MlKem768PublicKey,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct X25519KeyGenResponse {
    id: ID,
    pk: kx::X25519PublicKey,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768KeyGenResponse {
    id: ID,
    pk: kx::MlKem768PublicKey,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768DecapsResponse {
    id: ID,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct MlKem768EncapsResponse {
    id: ID,
    ct: kx::MlKem768Ciphertext,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct X25519DeriveResponse {
    id: ID,
}

impl X25519DeriveRequest {
    pub fn new(id: ID, key: kx::X25519PublicKey) -> Self {
        Self { id, key }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_key(&self) -> &kx::X25519PublicKey {
        &self.key
    }
}

impl MlKem768DecapsRequest {
    pub fn new(id: ID, ct: kx::MlKem768Ciphertext) -> Self {
        Self { id, ct }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_ciphertext(&self) -> &kx::MlKem768Ciphertext {
        &self.ct
    }
}

impl MlKem768EncapsRequest {
    pub fn new(key: kx::MlKem768PublicKey) -> Self {
        Self { key }
    }

    pub fn get_key(&self) -> &kx::MlKem768PublicKey {
        &self.key
    }
}

impl X25519KeyGenResponse {
    pub fn new(id: ID, pk: kx::X25519PublicKey) -> Self {
        Self { id, pk }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_pk(&self) -> &kx::X25519PublicKey {
        &self.pk
    }
}

impl MlKem768KeyGenResponse {
    pub fn new(id: ID, pk: kx::MlKem768PublicKey) -> Self {
        Self { id, pk }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_pk(&self) -> &kx::MlKem768PublicKey {
        &self.pk
    }
}

impl MlKem768DecapsResponse {
    pub fn new(id: ID) -> Self {
        Self { id }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }
}

impl MlKem768EncapsResponse {
    pub fn new(id: ID, ct: kx::MlKem768Ciphertext) -> Self {
        Self { id, ct }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }

    pub fn get_ct(&self) -> &kx::MlKem768Ciphertext {
        &self.ct
    }
}

impl X25519DeriveResponse {
    pub fn new(id: ID) -> Self {
        Self { id }
    }

    pub fn get_id(&self) -> &ID {
        &self.id
    }
}

impl From<&X25519KeyGenResponse> for X25519PublicKey {
    fn from(pk: &X25519KeyGenResponse) -> Self {
        Self::new(*pk.get_pk().as_bytes())
    }
}

impl From<&MlKem768KeyGenResponse> for MlKem768PublicKey {
    fn from(pk: &MlKem768KeyGenResponse) -> Self {
        Self::from(*pk.get_pk().as_bytes())
    }
}