use crate::{Error, RNG};

use libcrux_agent::{ID, hmac::HmacSha256Mac, key_store::KeyStore};
use libcrux_agent::aead::{CHACHA_NONCE_LEN, CHACHA_TAG_LEN};
use libcrux_agent::kx::{MlKem768Ciphertext, MlKem768PublicKey, X25519PublicKey};
use libcrux_agent::signatures::{EcDsaP256Signature, Ed25519Signature, SHA256};

use libcrux_ml_kem::mlkem768;
use rand::CryptoRng;
use rand::rand_core::UnwrapErr;
use std::sync::LazyLock;

static KEY_STORE: LazyLock<KeyStore> =
    LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

static EPHEMERAL_KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| {
    KeyStore::new( &mut UnwrapErr(RNG.write().unwrap())).expect("Failed to initialize KeyStore")
});

fn get_rng() -> Result<impl CryptoRng, Error> {
    let rng = RNG.write()
        .map_err(|_| Error::RNG)?;
    Ok(UnwrapErr(rng))
}

pub fn add_entropy(entropy: &[u8]) -> Result<(), Error>{
    RNG.write()
        .map_err(|_| Error::RNG)?
        .reseed(entropy, &[])
        .map_err(|_| Error::RNG)
}

pub fn ecdsa_p256_sign_for_id(id: &ID, message: &[u8]) -> Result<EcDsaP256Signature<SHA256>, Error> {
    KEY_STORE.ecdsa_p256_sign_for_id(id, message, &mut get_rng()?)
}

pub fn ed25519_sign_for_id(id: &ID, message: &[u8]) -> Result<Ed25519Signature, Error> {
    KEY_STORE.ed25519_sign_for_id(id, message)
}

pub fn chacha20poly1305_decrypt_for_id<'a>(id: &ID, plaintext: &'a mut [u8], nonce: &[u8; CHACHA_NONCE_LEN], tag: &[u8; CHACHA_TAG_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<&'a [u8], Error>{
    EPHEMERAL_KEY_STORE.chacha20poly1305_decrypt_for_id(id, plaintext, nonce, tag, ciphertext, aad)
}

pub fn chacha20poly1305_encrypt_for_id<'a>(id: &ID, ciphertext: &'a mut [u8], nonce: &[u8; CHACHA_NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Result<(&'a [u8], [u8; CHACHA_TAG_LEN]), Error>{
    EPHEMERAL_KEY_STORE.chacha20poly1305_encrypt_for_id(id, ciphertext, nonce, plaintext, aad)
}

pub fn x25519_generate_key_id() -> Result<(ID, X25519PublicKey), Error> {
    EPHEMERAL_KEY_STORE.x25519_generate_key(&mut get_rng()?)
}

pub fn mlkem_768_generate_key_id() -> Result<(ID, MlKem768PublicKey), Error> {
    EPHEMERAL_KEY_STORE.mlkem_768_generate_key(&mut get_rng()?)
}

pub fn x25519_derive_for_key_id(id: &ID, pk: &X25519PublicKey) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.x25519_derive_for_id(id, pk)
}

pub fn mlkem_768_decaps_for_id(id: &ID, ct: mlkem768::MlKem768Ciphertext) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.mlkem_768_decaps_for_id(id, ct)
}

pub fn mlkem_768_encaps_for_id(
    pk: &MlKem768PublicKey,
) -> Result<(ID, MlKem768Ciphertext), Error> {
    EPHEMERAL_KEY_STORE.mlkem_768_encaps_for_id(pk, &mut get_rng()?)
}

pub fn export_nonce(id: &ID) -> Result<[u8; 12], Error> {
    EPHEMERAL_KEY_STORE.export_nonce(id)
}

pub fn hkdf_extract_public_salt(id: &ID, salt: &[u8]) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.sha256_hkdf_extract_public_salt(id, salt)
}

pub fn hkdf_extract_secret_salt(id: Option<&ID>, salt: &ID) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.sha256_hkdf_extract_secret_salt(id, salt)
}

pub fn hkdf_expand(id: &ID, info: &[u8], output_len: usize) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.sha256_hkdf_expand(id, info, output_len)
}

pub fn hmac_sha2_256_authenticate(id: &ID, payload: &[u8]) -> Result<HmacSha256Mac, Error> {
    EPHEMERAL_KEY_STORE.hmac_sha2_256_authenticate(id, payload)
}
