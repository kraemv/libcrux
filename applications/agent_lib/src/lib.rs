use zerocopy::*;

#[derive(Clone, Debug, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum Error {
    Derive,
    DuplicateKey,
    Encoding,
    IO,
    KeyExchange,
    MalformedRequest,
    MalformedResponse,
    NoAgent,
    PublicKey,
    Signing,
    UnknownID,
    Unsupported,
}

type ID = [u8; 32];

pub mod agent;
pub mod key_store;
pub mod kex_messages;
pub mod kx;
pub mod signing_messages;
pub mod messages;
pub mod signatures;
