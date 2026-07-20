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
pub trait Hash<const N: usize>: Send + Sync {
    const SCHEME: HashAlgo;

    fn init() -> Self;

    fn hash(payload: &[u8]) -> [u8; N];

    fn update(&mut self, payload: &[u8]) -> &mut Self;

    fn fork(&self) -> Self;

    fn finalize(self) -> [u8; N];
}

impl Hash<{ libcrux_sha2::SHA256_LENGTH }> for libcrux_sha2::Sha256 {
    const SCHEME: HashAlgo = HashAlgo::Sha2_256;

    fn init() -> Self {
        libcrux_sha2::Sha256::new()
    }

    fn hash(payload: &[u8]) -> [u8; libcrux_sha2::SHA256_LENGTH] {
        libcrux_sha2::sha256(payload)
    }

    fn update(&mut self, payload: &[u8]) -> &mut Self{
        Digest::update(self, payload);
        self
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn finalize(self) -> [u8; libcrux_sha2::SHA256_LENGTH] {
        let mut digest = [0u8; libcrux_sha2::SHA256_LENGTH];
        self.finish(&mut digest);
        digest
    }
}
