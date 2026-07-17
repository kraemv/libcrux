use std::sync::PoisonError;

use zerocopy::*;
use libcrux_traits::ecdh::arrayref::GenerateSecretError;

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
    InvalidTag,
    IO,
    HKDF,
    KeyExchange,
    MAC,
    MalformedMessage,
    NoAgent,
    PublicKey,
    RNG,
    Signing,
    Sync,
    UnknownID,
    Unsupported,
}

impl<A, B: TryFromBytes> From<TryReadError<A, B>> for Error{
    fn from(_: TryReadError<A, B>) -> Self {
        Error::MalformedMessage
    }
}

impl<A, B: TryFromBytes> From<TryCastError<A, B>> for Error{
    fn from(_: TryCastError<A, B>) -> Self {
        Error::MalformedMessage
    }
}

impl<T> From<PoisonError<T>> for Error{
    fn from(_: PoisonError<T>) -> Self {
        Error::Sync
    }
}

impl From<GenerateSecretError> for Error{
    fn from(_: GenerateSecretError) -> Self {
        Error::KeyExchange
    }
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
