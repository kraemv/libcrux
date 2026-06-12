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

pub struct Lib{}
pub struct AgentLib{}

impl Implementation for Lib {}
impl Implementation for AgentLib {}

pub trait NetworkObject: Send + Sync + Sized + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {}

impl NetworkObject for Vec<u8> {}

impl<Scheme: Send + Sync> NetworkObject for KeyID<Scheme>{}

// TODO: Add Impl generic for ambiguos types like salts and KEM PK

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
