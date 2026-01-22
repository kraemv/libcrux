use crate::signature::{Error, Signature, SigningKey, SigningKeyType};
use crate::RNG;
use libcrux_kmac as kmac;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

static KEY_STORE: LazyLock<RwLock<KeyStore>> = LazyLock::new(|| RwLock::new(KeyStore::new()));

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
    entries: HashMap<[u8; 32], KeyStoreEntry>,
}

impl KeyStore {
    fn new() -> Self {
        let mut root_key = [0u8; 32];
        RNG.write().unwrap().fill_bytes(&mut root_key);
        KeyStore {
            root_key: root_key,
            entries: HashMap::new(),
        }
    }

    fn sign_for_id(&self, id: [u8; 32], message: &[u8]) -> Result<Signature, Error> {
        self.entries
            .get(&id)
            .ok_or(Error::InvalidKey)?
            .get_key()
            .sign(message)
    }

    fn add_entry(&mut self, entry: KeyStoreEntry) {
        self.entries.insert(entry.id, entry);
    }
}

pub fn sign_for_id(id: [u8; 32], message: &[u8]) -> Result<Signature, Error> {
    let store = KEY_STORE.read().unwrap();
    store.sign_for_id(id, message)
}

pub fn add_entry(entry: KeyStoreEntry) {
    let mut store = KEY_STORE.write().unwrap();
    store.add_entry(entry)
}

pub fn add_key(key: SecretKey) {
    let bytes: &[u8] = match &key {
        SecretKey::SigningKey(sig_key) => sig_key.as_ref(),
    };
    let customization: &[u8] = match key {
        SecretKey::SigningKey(SigningKeyType::EcDsaP256(_)) => b"EcDsaP256Key",
        SecretKey::SigningKey(SigningKeyType::Ed25519(_)) => b"Ed25519Key",
    };
    let mut tag = [0u8; 32];
    let store = KEY_STORE.read().unwrap();
    let tag = kmac::kmac_128(&mut tag, &store.root_key, bytes, customization)
        .try_into()
        .unwrap();

    let mut store = KEY_STORE.write().unwrap();
    let entry = KeyStoreEntry::new(tag, key);
    store.add_entry(entry)
}
