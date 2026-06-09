use libcrux_sha2;
use libcrux_traits::Digest;

pub enum HashAlgo {
    Sha2_256,
}
pub trait Hash<const N: usize>: Digest<N> + Clone + Send + Sync{
    fn init() -> Self;
    
    fn scheme() -> HashAlgo;
}

impl Hash<{libcrux_sha2::SHA256_LENGTH}> for libcrux_sha2::Sha256 {
    fn init() -> Self {
        libcrux_sha2::Sha256::new()    
    }

    fn scheme() -> HashAlgo {
        HashAlgo::Sha2_256
    }
}