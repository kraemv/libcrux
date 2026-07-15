use zerocopy::*;

pub(crate) use id::{InnerRndBytes, ID_SIZE};
pub use id::{KeyID, ID};

#[derive(Clone, Debug, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum Error {
    AEAD,
    Derive,
    DuplicateKey,
    Encoding,
    Expand,
    IO,
    HKDF,
    KeyExchange,
    MAC,
    MalformedRequest,
    MalformedResponse,
    NoAgent,
    PublicKey,
    RNG,
    Signing,
    Sync,
    UnknownID,
    Unsupported,
}

pub mod aead;
pub mod aead_messages;
pub mod agent;
pub mod hkdf;
pub mod hkdf_messages;
pub mod hmac;
pub mod hmac_messages;
mod id;
pub mod ipc;
pub mod kex_messages;
pub mod key_store;
pub mod kx;
pub mod messages;
pub mod rng_messages;
pub mod signatures;
pub mod signing_messages;
