use crate::signature::{Error, Signature, SigningKey, SigningKeyType, VerificationKeyType};
use crate::RNG;
use libcrux_kmac as kmac;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

static KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| KeyStore::new());

pub enum SecretKey {
    SigningKey(SigningKeyType),
    // SessionTicket(SessionTicket),
}

impl SecretKey {
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match self {
            SecretKey::SigningKey(key) => {
                let mut rng_guard = RNG.write().unwrap();
                key.sign(message, &mut *rng_guard)
            } // _ => Err(Error::InvalidKey),
        }
    }
}
// NIST DRBG
pub struct KeyStoreEntry {
    id: [u8; 32],
    key: SecretKey,
}

impl KeyStoreEntry {
    pub fn new(id: [u8; 32], key: SecretKey) -> Self {
        Self { id: id, key: key }
    }

    pub fn get_key(&self) -> &SecretKey {
        &self.key
    }
}

struct KeyStore {
    root_key: [u8; 32],
    entries: RwLock<HashMap<[u8; 32], KeyStoreEntry>>,
}

impl KeyStore {
    fn new() -> Self {
        let mut root_key = [0u8; 32];
        RNG.write().unwrap().fill_bytes(&mut root_key);
        KeyStore {
            root_key: root_key,
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn sign_for_id(&self, id: [u8; 32], message: &[u8]) -> Result<Signature, Error> {
        self.entries
            .read()
            .unwrap()
            .get(&id)
            .ok_or(Error::InvalidKey)?
            .get_key()
            .sign(message)
    }

    fn add_entry(&self, entry: KeyStoreEntry) {
        self.entries
            .write()
            .unwrap()
            .insert(entry.id, entry);
    }
}

pub fn sign_for_id(id: [u8; 32], message: &[u8]) -> Result<Signature, Error> {
    KEY_STORE.sign_for_id(id, message)
}

pub fn add_entry(entry: KeyStoreEntry) {
    KEY_STORE.add_entry(entry);
}

pub fn add_key(key: SecretKey) -> ([u8; 32], VerificationKeyType){
    let bytes: &[u8] = match &key {
        SecretKey::SigningKey(sig_key) => sig_key.as_ref(),
    };
    let customization: &[u8] = match key {
        SecretKey::SigningKey(SigningKeyType::EcDsaP256(_)) => b"EcDsaP256Key",
        SecretKey::SigningKey(SigningKeyType::Ed25519(_)) => b"Ed25519Key",
    };
    let mut tag = [0u8; 32];
    let tag = kmac::kmac_128(&mut tag, &KEY_STORE.root_key, bytes, customization)
        .try_into()
        .unwrap();
    
    let pk: VerificationKeyType = match &key {
        SecretKey::SigningKey(sig_key) => sig_key.to_public().expect("Public Key creation failed"),
    };
    
    let entry = KeyStoreEntry::new(tag, key);
    KEY_STORE.add_entry(entry);
    
    (tag, pk) 
}
