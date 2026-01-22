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

static RNG: LazyLock<RwLock<ChaCha20Rng>> =
    LazyLock::new(|| RwLock::new(ChaCha20Rng::from_os_rng()));
