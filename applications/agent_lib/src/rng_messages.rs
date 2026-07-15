pub struct EntropyRequest<'a> {
    entropy: &'a [u8],
}

impl<'a> From<&'a [u8]> for EntropyRequest<'a> {
    fn from(entropy: &'a [u8]) -> Self {
        Self { entropy }
    }
}
impl AsRef<[u8]> for EntropyRequest<'_> {
    fn as_ref(&self) -> &[u8] {
        self.entropy
    }
}
