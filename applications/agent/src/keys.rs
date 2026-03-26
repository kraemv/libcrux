// use crate::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, Error, Signature, SigningKey, SigningKeyType, VerificationKeyType};
use crate::{Error, RNG};
use agent_lib::{key_store::KeyStore, signatures::{EcDsaP256Signature, Ed25519Signature}};
use std::sync::{LazyLock};

static KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

pub fn sign_for_ecdsa_p256_id(id: [u8; 32], message: &[u8]) -> Result<EcDsaP256Signature, Error> {
    KEY_STORE.sign_for_ecdsa_p256_id(id, message, &mut RNG.write().unwrap())
}

pub fn sign_for_ed25519_id(id: [u8; 32], message: &[u8]) -> Result<Ed25519Signature, Error> {
    KEY_STORE.sign_for_ed25519_id(id, message)
}
