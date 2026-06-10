use std::marker::PhantomData;

use libcrux_agent::ID;

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod kem;
pub mod nike;
mod provider;
pub mod signature;

pub type RandomKey = Vec<u8>;

pub trait Implementation {}

// struct Lib{}
pub struct AgentLib{}

// impl Implementation for Lib {}
impl Implementation for AgentLib {}

pub trait NetworkObject: Send + Sync + Sized + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {}

impl NetworkObject for Vec<u8> {}

pub struct KeyID<Scheme> {
    id: ID,
    agent_idx: usize,
    scheme: PhantomData<Scheme>
}

pub enum ConversionError {
    MalformedID,
    NoIndex,
}

const USIZE_SIZE: usize = size_of::<usize>();
const ID_SIZE: usize = size_of::<ID>();
const KEY_ID_SIZE: usize = ID_SIZE + USIZE_SIZE;

impl<Scheme> TryFrom<&[u8]> for KeyID<Scheme> {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (id, idx) = value.split_at_checked(size_of::<ID>()).ok_or(ConversionError::MalformedID)?;
        let id = ID::try_from(id).map_err(|_| ConversionError::MalformedID)?;
        let agent_idx = usize::from_be_bytes(idx.try_into().map_err(|_| ConversionError::NoIndex)?);
        Ok(KeyID::<Scheme> { id, agent_idx, scheme: PhantomData })
    }
}

impl<Scheme> From<[u8; KEY_ID_SIZE]> for KeyID<Scheme> {
    fn from(value: [u8; KEY_ID_SIZE]) -> Self {
        let id= value.first_chunk::<ID_SIZE>().unwrap();
        let id = ID::from(*id);
        let agent_idx = usize::from_be_bytes(*value.last_chunk::<USIZE_SIZE>().unwrap());
        KeyID::<Scheme> { id, agent_idx, scheme: PhantomData }
    }
}
// TODO: Add Impl generic for ambiguos types like salts and KEM PK
// TODO: Add generic Agent key for id/idx pair

/*
Desired primitives / functionalities:
    All functions return a result
- Sign (keygen()->sk,pk; sign(sk, m)->sig; vrfy(pk, m, sig)->bool)
- KEM (keygen()->sk,pk; encaps(pk)->ct,shk; decaps(sk, ct)->shk)
- NIKE (Non-interactive key-exchange)
    (keygen()->sk,pk; shared_key(sk, pk)->shk)
- AEAD (keygen()->sk; enc(sk, m, ad, nonce)->ct, tag)??? key-commitment?
- KDF/PRF/Dual-PRF???
- Cyptographic Hash / XOF (extend(seed)->rand)
*/
// One Agent per application to allow transitions of keys
// KDF produce n bytes symmetric keys
// Symmetric keys have transitions from untyped to application specific
