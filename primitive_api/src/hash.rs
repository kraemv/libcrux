use libcrux_sha2;
use libcrux_traits::Digest;

pub enum HashAlgo {
    Sha2_256,
}

pub type DefaultHash = libcrux_sha2::Sha256;

/// Minimal example:
/// ```
/// use libcrux_primitive_api::hash::*;
/// use libcrux_traits::Digest;
/// 
/// let msg = b"Insight must precede application";
/// let mut digest = [0u8; 32];
/// 
/// DefaultHash::hash(&mut digest, msg)
/// ```
pub trait Hash<const N: usize>: Digest<N> + Send + Sync{
    fn init() -> Self;

    fn fork(&self) -> Self;
    
    fn scheme() -> HashAlgo;
}

impl Hash<{libcrux_sha2::SHA256_LENGTH}> for libcrux_sha2::Sha256 {
    fn init() -> Self {
        libcrux_sha2::Sha256::new()    
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn scheme() -> HashAlgo {
        HashAlgo::Sha2_256
    }
}