pub use libcrux_agent::KeyID;

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

pub struct Lib {}
pub struct AgentLib {}

impl Implementation for Lib {}
impl Implementation for AgentLib {}

pub trait NetworkObject: Send + Sync + Sized + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {}

impl NetworkObject for Vec<u8> {}

impl<Scheme: Send + Sync> NetworkObject for KeyID<Scheme> {}
