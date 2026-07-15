use libcrux_chacha20poly1305 as chacha20poly1305;

use crate::provider::get_agent;
use crate::{KeyID, NetworkObject};
pub use libcrux_agent::aead::ChaCha20Poly1305;
use libcrux_agent::aead::{AeadNonce, AeadTag};

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

pub type DefaultAEADKey = chacha20poly1305::Key;

/// Minimal example:
/// ```
/// use rand::{RngCore, SeedableRng};
/// use rand_chacha::ChaChaRng;
///
/// use libcrux_primitive_api::aead::*;
///
/// let mut rng = ChaChaRng::from_os_rng();
/// let mut key_material = [0u8; 32];
/// let mut nonce = [0u8; 12];
/// rng.fill_bytes(&mut key_material);
/// rng.fill_bytes(&mut nonce);
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
/// let (ct, tag) = key.encrypt_msg(&mut ct, nonce_1, aad, msg).expect("Encryption failed");
/// let pt = match key.decrypt_msg(&mut pt, nonce_2, aad, ct, tag) {
///     Ok(msg) => msg,
///     Err(Error::InvalidTag) => return println!("Invalid Tag"),
///     Err(Error::Decrypt) => return println!("Decryption had an internal error"),
///     _ => return println!("Unexpected Error"),
/// };
///
/// assert_eq!(msg, pt)
/// ```
pub trait AEADKey<const KEY_SIZE: usize>: Send + Sync + From<[u8; KEY_SIZE]> {
    type Tag: NetworkObject;
    type Nonce: NetworkObject;

    const SCHEME: AEADAlgorithm;
    const KEY_LEN: usize;

    fn encrypt_msg<'a>(
        &self,
        ct: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(&'a [u8], Self::Tag), Error>;

    fn decrypt_msg<'a>(
        &self,
        pt: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Self::Tag,
    ) -> Result<&'a [u8], Error>;
}

impl AEADKey<{ chacha20poly1305::KEY_LEN }> for chacha20poly1305::Key {
    type Tag = AeadTag<{ chacha20poly1305::TAG_LEN }>;
    type Nonce = AeadNonce<{ chacha20poly1305::NONCE_LEN }>;

    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;
    const KEY_LEN: usize = chacha20poly1305::KEY_LEN;

    fn encrypt_msg<'a>(
        &self,
        ct: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(&'a [u8], Self::Tag), Error> {
        let mut tag = chacha20poly1305::Tag::from([0u8; chacha20poly1305::TAG_LEN]);
        let nonce_bytes: [u8; chacha20poly1305::NONCE_LEN] = nonce.into();
        let nonce = nonce_bytes.into();
        self.encrypt(ct, &mut tag, &nonce, aad, plaintext)
            .map(|()| (&ct[..], (*tag.as_ref()).into()))
            .map_err(|_| Error::Encrypt)
    }

    fn decrypt_msg<'a>(
        &self,
        pt: &'a mut [u8],
        nonce: Self::Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Self::Tag,
    ) -> Result<&'a [u8], Error> {
        let nonce: [u8; chacha20poly1305::NONCE_LEN] = nonce.into();
        let tag: [u8; chacha20poly1305::TAG_LEN] = tag.into();
        self.decrypt(pt, &nonce.into(), aad, ciphertext, &tag.into())
            .map_err(map_libcrux_decrypt_error)
            .map(|()| &pt[..])
    }
}

impl AEADKey<{ size_of::<KeyID<ChaCha20Poly1305>>() }> for KeyID<ChaCha20Poly1305> {
    type Tag = AeadTag<{ chacha20poly1305::TAG_LEN }>;
    type Nonce = AeadNonce<{ chacha20poly1305::NONCE_LEN }>;

    const SCHEME: AEADAlgorithm = AEADAlgorithm::ChaCha20Poly1305;
    const KEY_LEN: usize = chacha20poly1305::KEY_LEN;

    fn encrypt_msg<'a>(
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

    fn decrypt_msg<'a>(
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

fn map_libcrux_decrypt_error(err: libcrux_traits::aead::arrayref::DecryptError) -> Error {
    match err {
        libcrux_traits::aead::arrayref::DecryptError::InvalidTag => Error::InvalidTag,
        libcrux_traits::aead::arrayref::DecryptError::Unknown => {
            Error::Internal("Unknown Error".to_string())
        }
        _ => Error::Decrypt,
    }
}

impl<const N: usize> NetworkObject for AeadNonce<N> {}
impl<const N: usize> NetworkObject for AeadTag<N> {}
