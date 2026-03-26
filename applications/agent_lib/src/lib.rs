use zerocopy::*;

#[derive(Clone, Debug, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[repr(u8)]
pub enum Error {
    DuplicateKey,
    Encoding,
    IO,
    MalformedRequest,
    MalformedResponse,
    NoAgent,
    PublicKey,
    Signing,
    UnknownID,
    Unsupported,
}

pub mod agent;
pub mod messages;
pub mod key_store;
pub mod signatures;