// use crate::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, Error, Signature, SigningKey, SigningKeyType, VerificationKeyType};
use crate::{Error, RNG};
use libcrux_agent::{
    key_store::KeyStore, kx::{MlKem768PublicKey, X25519PublicKey}, signatures::{EcDsaP256Signature, Ed25519Signature}
};
use libcrux_ml_kem::mlkem768 as mlkem768;
use std::sync::LazyLock;

static KEY_STORE: LazyLock<KeyStore> =
    LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

static EPHEMERAL_KEY_STORE: LazyLock<KeyStore> =
    LazyLock::new(|| KeyStore::new(&mut RNG.write().unwrap()).expect("Failed to initialize KeyStore"));

pub fn sign_for_ecdsa_p256_id(id: [u8; 32], message: &[u8]) -> Result<EcDsaP256Signature, Error> {
    KEY_STORE.sign_for_ecdsa_p256_id(id, message, &mut RNG.write().unwrap())
}

pub fn sign_for_ed25519_id(id: [u8; 32], message: &[u8]) -> Result<Ed25519Signature, Error> {
    KEY_STORE.sign_for_ed25519_id(id, message)
}

pub fn generate_x25519_key_id() -> Result<([u8; 32], X25519PublicKey), Error>{
    EPHEMERAL_KEY_STORE.generate_x25519_key(&mut RNG.write().unwrap())
}


pub fn generate_mlkem768_key_id() -> Result<([u8; 32], MlKem768PublicKey), Error>{
    EPHEMERAL_KEY_STORE.generate_mlkem_768_key(&mut RNG.write().unwrap())
}

pub fn derive_for_x25519_key_id(id: [u8; 32], pk: &X25519PublicKey) -> Result<[u8; 32], Error>{
    EPHEMERAL_KEY_STORE.derive_for_x25519_id(id, pk)
}


pub fn decaps_for_mlkem768_id(id: [u8; 32], ct: &mlkem768::MlKem768Ciphertext) -> Result<[u8; 32], Error>{
    EPHEMERAL_KEY_STORE.decaps_for_mlkem768_id(id, ct)
}


pub fn encaps_for_mlkem768_id(pk: &mlkem768::MlKem768PublicKey) -> Result<([u8; 32], mlkem768::MlKem768Ciphertext), Error>{
    EPHEMERAL_KEY_STORE.encaps_for_mlkem768_id(pk, &mut RNG.write().unwrap())
}

pub fn export_key(id: [u8; 32]) -> Result<[u8; 32], Error> {
    EPHEMERAL_KEY_STORE.export_shared_secret(id)
}