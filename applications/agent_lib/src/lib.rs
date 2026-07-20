use core::fmt;
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
    Decapsulate,
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
    Rejected,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AEAD => write!(f, "AEAD error"),
            Error::Derive => write!(f, "key derivation error"),
            Error::Decapsulate => write!(f, "Decapsulation failed"),
            Error::DuplicateKey => write!(f, "duplicate key"),
            Error::Encoding => write!(f, "encoding error"),
            Error::Expand => write!(f, "expand error"),
            Error::InvalidTag => write!(f, "invalid tag"),
            Error::IO => write!(f, "I/O error"),
            Error::HKDF => write!(f, "HKDF error"),
            Error::KeyExchange => write!(f, "key exchange error"),
            Error::MAC => write!(f, "MAC error"),
            Error::MalformedMessage => write!(f, "malformed message"),
            Error::NoAgent => write!(f, "no agent"),
            Error::PublicKey => write!(f, "public key error"),
            Error::Rejected => write!(f, "Rejected ciphertext"),
            Error::RNG => write!(f, "random number generator error"),
            Error::Signing => write!(f, "signing error"),
            Error::Sync => write!(f, "synchronization error"),
            Error::UnknownID => write!(f, "unknown ID"),
            Error::Unsupported => write!(f, "unsupported operation"),
        }
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
