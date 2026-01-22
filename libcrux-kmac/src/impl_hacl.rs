macro_rules! impl_kmac {
    ($name:ident,$fun:path) => {
        /// Compute KMAC.
        ///
        /// Note that this function panics if `key` or `data` is larger than 2**32 bytes.
        /// This ensures that all values are in the range valid to be consumed by hacl-rs.
        #[inline(always)]
        pub fn $name<'a>(tag: &'a mut [u8], key: &[u8], data: &[u8], customization: &[u8]) -> &'a [u8]{
            $fun(
                tag,
                tag.len(),
                key,
                key.len(),
                data,
                customization,
                customization.len()
            )
        }
    };
}

impl_kmac!(kmac_128, crate::hacl::kmac::compute_kmac_128);
impl_kmac!(kmac_256, crate::hacl::kmac::compute_kmac_256);
