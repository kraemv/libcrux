use libcrux_chacha20poly1305 as chacha20poly1305;
use zeroize::ZeroizeOnDrop;

use crate::provider::get_agent;
use crate::{KeyID, NetworkObject};
pub use libcrux_agent::aead::ChaCha20Poly1305;
use libcrux_agent::aead::{AeadNonce, AeadTag, ChaCha20Poly1305Key};
use libcrux_agent::Error as AgentError;

#[derive(Debug)]
pub enum Error {
    Internal(String),
    Decrypt,
    Encrypt,
    InvalidTag,
}

pub enum AEADAlgorithm {
    // AesGcm128,
    ChaCha20Poly1305,
}

pub type DefaultAEADKey = ChaCha20Poly1305Key;

/// Minimal example:
/// ```
/// use rand::{TryRng, rngs::SysRng};
/// use libcrux_primitive_api::aead::*;
///
/// let mut rng = SysRng;
/// let mut key_material = [0u8; 32];
/// let mut nonce = [0u8; 12];
/// rng.try_fill_bytes(&mut key_material).unwrap();
/// rng.try_fill_bytes(&mut nonce).unwrap();
///
/// let key = DefaultAEADKey::from(key_material);
/// let nonce_1 = <DefaultAEADKey as AEADKey<32>>::Nonce::try_from(nonce).expect("Nonce generation failed");
/// let nonce_2 = <DefaultAEADKey as AEADKey<32>>::Nonce::try_from(nonce).expect("Nonce generation failed");
/// let mut ct = [0u8; 12];
/// let mut pt = [0u8; 12];
/// let msg = b"Test message";
/// let aad = b"AEAD showcase";
///
///
/// let (ct, tag) = key.encrypt(&mut ct, nonce_1, aad, msg).expect("Encryption failed");
/// let pt = match key.decrypt(&mut pt, nonce_2, aad, ct, tag) {
///     Ok(msg) => msg,
///     Err(Error::InvalidTag) => return println!("Invalid Tag"),
///     Err(Error::Decrypt) => return println!("Decryption had an internal error"),
///     _ => return println!("Unexpected Error"),
/// };
///
/// assert_eq!(msg, pt)
/// ```
pub trait AEADKey: Send + Sync + for<'a> TryFrom<&'a [u8]> + ZeroizeOnDrop{
    type Tag: NetworkObject;
    type Nonce: NetworkObject;

    const SCHEME: AEADAlgorithm;
    const KEY_LEN: usize;
    const KEY_SIZE: usize;

    fn encrypt<'a>(
        &self,
        ct: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(&'a [u8], Self::Tag), Error>;

    fn decrypt<'a>(
        &self,
        pt: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Self::Tag,
    ) -> Result<&'a [u8], Error>;
}

impl AEADKey for ChaCha20Poly1305Key {
    type Tag = AeadTag<{ chacha20poly1305::TAG_LEN }>;
    type Nonce = AeadNonce<{ chacha20poly1305::NONCE_LEN }>;

    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;
    const KEY_LEN: usize = chacha20poly1305::KEY_LEN;
    const KEY_SIZE: usize = chacha20poly1305::KEY_LEN;

    fn encrypt<'a>(
        &self,
        ct: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(&'a [u8], Self::Tag), Error> {
        self.encrypt_msg(ct, nonce, aad, plaintext).map_err(|_| Error::Encrypt)
    }

    fn decrypt<'a>(
        &self,
        pt: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Self::Tag,
    ) -> Result<&'a [u8], Error> {
        self.decrypt_msg(pt, nonce, aad, ciphertext, tag)
            .map_err(map_library_error)
    }
}

fn map_library_error(err: AgentError) -> Error {
    match err {
        AgentError::AEAD => Error::Decrypt,
        AgentError::InvalidTag => Error::InvalidTag,
        _ => Error::Internal("Internal Error occured".into()),
    }
}

impl AEADKey for KeyID<ChaCha20Poly1305> {
    type Tag = AeadTag<{ chacha20poly1305::TAG_LEN }>;
    type Nonce = AeadNonce<{ chacha20poly1305::NONCE_LEN }>;

    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;
    const KEY_LEN: usize = chacha20poly1305::KEY_LEN;
    const KEY_SIZE: usize = size_of::<KeyID<ChaCha20Poly1305>>();
    fn encrypt<'a>(
        &self,
        ct: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(&'a [u8], Self::Tag), Error> {
        let agent = get_agent().ok_or_else(|| Error::Internal("No agent available".into()))?;

        agent
            .chacha20poly1305_encrypt_for_id(
                self.get_id().clone(),
                ct,
                nonce.into(),
                plaintext,
                aad,
            )
            .map_err(|_| Error::Encrypt)
    }

    fn decrypt<'a>(
        &self,
        pt: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Self::Tag,
    ) -> Result<&'a [u8], Error> {
        let agent = get_agent().ok_or_else(|| Error::Internal("No agent available".into()))?;

        agent
            .chacha20poly1305_decrypt_for_id(
                self.get_id().clone(),
                pt,
                nonce.into(),
                tag.into(),
                ciphertext,
                aad,
            )
            .map_err(|_| Error::Decrypt)
    }
}

impl<const N: usize> NetworkObject for AeadNonce<N> {}
impl<const N: usize> NetworkObject for AeadTag<N> {}
