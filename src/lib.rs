//! # libcrux
//!
//! A high-assurance cryptography library.

#![no_std]

#[cfg(feature = "std")]
extern crate std;
use std::sync::{LazyLock, RwLock};
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc as std;

use rand::SeedableRng;
use rand_chacha::*;

pub mod algorithms;
pub mod primitives;
pub mod protocols;

// Key management
pub(crate) mod keys;

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

static RNG: LazyLock<RwLock<ChaCha20Rng>> =
    LazyLock::new(|| RwLock::new(ChaCha20Rng::from_os_rng()));
