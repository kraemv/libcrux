// use crate::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, Error, Signature, SigningKey, SigningKeyType, VerificationKeyType};
use crate::{Error, RNG};
use libcrux_agent::{
    ID, key_store::KeyStore, kx::{MlKem768Ciphertext, MlKem768PublicKey, X25519PublicKey}, signatures::{EcDsaP256Signature, Ed25519Signature, SHA256},
};
use libcrux_ml_kem::mlkem768;
use std::sync::LazyLock;

static KEY_STORE: LazyLock<KeyStore> =
    LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

static EPHEMERAL_KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| {
    KeyStore::new(&mut RNG.write().unwrap()).expect("Failed to initialize KeyStore")
});

pub fn ecdsa_p256_sign_for_id(id: ID, message: &[u8]) -> Result<EcDsaP256Signature<SHA256>, Error> {
    KEY_STORE.ecdsa_p256_sign_for_id(id, message, &mut RNG.write().unwrap())
}

pub fn ed25519_sign_for_id(id: ID, message: &[u8]) -> Result<Ed25519Signature, Error> {
    KEY_STORE.ed25519_sign_for_id(id, message)
}

pub fn x25519_generate_key_id() -> Result<(ID, X25519PublicKey), Error> {
    EPHEMERAL_KEY_STORE.x25519_generate_key(&mut RNG.write().unwrap())
}

pub fn mlkem_768_generate_key_id() -> Result<(ID, MlKem768PublicKey), Error> {
    EPHEMERAL_KEY_STORE.mlkem_768_generate_key(&mut RNG.write().unwrap())
}

pub fn x25519_derive_for_key_id(id: ID, pk: &X25519PublicKey) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.x25519_derive_for_id(id, pk)
}

pub fn mlkem_768_decaps_for_id(id: ID, ct: mlkem768::MlKem768Ciphertext) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.mlkem_768_decaps_for_id(id, ct)
}

pub fn mlkem_768_encaps_for_id(
    pk: &MlKem768PublicKey,
) -> Result<(ID, MlKem768Ciphertext), Error> {
    EPHEMERAL_KEY_STORE.mlkem_768_encaps_for_id(pk, &mut RNG.write().unwrap())
}

pub fn export_key_material(id: ID) -> Result<Vec<u8>, Error> {
    EPHEMERAL_KEY_STORE.export_key_material(id)
}

pub fn hkdf_extract_public_salt(id: Option<ID>, salt: Option<&[u8]>) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.sha256_hkdf_extract_public_salt(id, salt)
}

pub fn hkdf_extract_secret_salt(id: Option<ID>, salt: Option<ID>) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.sha256_hkdf_extract_secret_salt(id, salt)
}

pub fn hkdf_expand(id: ID, info: &[u8], output_len: usize) -> Result<ID, Error> {
    EPHEMERAL_KEY_STORE.sha256_hkdf_expand(id, info, output_len)
}
