pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod kem;
pub mod nike;
mod provider;
pub mod signature;

pub type RandomKey = Vec<u8>;

pub trait NetworkObject: Send + Sync + Sized + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> {}

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
