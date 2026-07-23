pub use libcrux_agent::KeyID;

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod mac;
pub mod kem;
pub mod nike;
mod provider;
pub mod signature;

pub trait Provider {}

pub struct Lib {}
pub struct AgentLib {}

impl Provider for Lib {}
impl Provider for AgentLib {}

pub trait NetworkObject: Send + Sync + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {}

impl NetworkObject for Vec<u8> {}

impl<Scheme: Send + Sync> NetworkObject for KeyID<Scheme> {}