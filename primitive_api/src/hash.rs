use libcrux_sha2;

pub struct Sha2_256;

pub enum HashAlgo {
    Sha2_256,
}
pub trait Hash<const N: usize> {
    fn digest(&self, msg: &[u8]) -> [u8; N];

    fn scheme() -> HashAlgo;
}

impl Hash<{libcrux_sha2::SHA256_LENGTH}> for Sha2_256 {
    fn digest(&self, msg: &[u8]) -> [u8; libcrux_sha2::SHA256_LENGTH]
    {
        libcrux_sha2::sha256(msg)
    }

    fn scheme() -> HashAlgo {
        HashAlgo::Sha2_256
    }
}