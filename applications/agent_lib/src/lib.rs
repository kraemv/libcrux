use zerocopy::*;

#[derive(Clone, Debug, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum Error {
    Derive,
    DuplicateKey,
    Encoding,
    IO,
    HKDF,
    KeyExchange,
    MalformedRequest,
    MalformedResponse,
    NoAgent,
    PublicKey,
    Signing,
    UnknownID,
    Unsupported,
}

pub(crate) const ID_SIZE: usize = 32;
pub type ID = [u8; ID_SIZE];

pub mod agent;
pub mod ipc;
pub mod kex_messages;
pub mod key_store;
pub mod kx;
pub mod hkdf;
pub mod hkdf_messages;
pub mod messages;
pub mod signatures;
pub mod signing_messages;
