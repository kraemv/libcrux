use libcrux_hmac;

trait Hmac {
    fn tag_lenth(&self) -> usize;
}
pub struct HmacSha2_256;

impl Hmac for HmacSha2_256 {
    fn tag_lenth(&self) -> usize {
        32
    }
}

// A signature that holds its actual value
pub struct HmacSha256Mac ([u8; 32]);

pub struct HmacSha256Key<'a> (&'a[u8]);

impl HmacSha256Mac {
    pub fn new(mac: [u8; 32]) -> Self {
        Self(mac)
    }

    pub fn get_mac(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'a> HmacSha256Key<'a> {
    pub fn new(key: &'a[u8]) -> Self {
        Self (key)
    }

    pub fn get_key(&self) -> &[u8] {
        self.0
    }

    pub fn sign(
        &self,
        message: &[u8],
    ) -> HmacSha256Mac {
        let mut mac = [0u8; 32];
        libcrux_hmac::hmac_sha2_256(&mut mac, self.0, message);
        HmacSha256Mac::new(mac)
    }
}

pub(crate) const fn tag_lenth<T: ~const Hmac>(alg: T) -> usize {
    alg.tag_length()
}