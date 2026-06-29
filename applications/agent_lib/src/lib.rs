use zerocopy::*;

pub use id::{KeyID, ID};
pub(crate) use id::{ID_SIZE, InnerRndBytes};

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
mod id;
pub mod ipc;
pub mod hmac;
pub mod hmac_messages;
pub mod kex_messages;
pub mod key_store;
pub mod kx;
pub mod hkdf;
pub mod hkdf_messages;
pub mod messages;
pub mod signatures;
pub mod signing_messages;
pub mod rng_messages;
