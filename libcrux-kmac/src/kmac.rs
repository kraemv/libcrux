//! KMAC
//!
//! This crate implements KMAC.
#![no_std]

extern crate alloc;

#[cfg(not(feature = "expose-hacl"))]
mod hacl {
    pub(crate) mod kmac;
}

#[cfg(feature = "expose-hacl")]
pub mod hacl {
    pub mod kmac;
}


mod impl_hacl;
pub use impl_hacl::*;
