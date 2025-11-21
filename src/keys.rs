use crate::std::vec::Vec;
use std::sync::{LazyLock, RwLock};
use crate::signature::{Error, Signature, SigningKey, SigningKeyType, SigInfo};
use rand::CryptoRng;

static KEY_STORE: LazyLock<RwLock<KeyStore>> = LazyLock::new(|| RwLock::new(KeyStore::new()));

pub enum SecretKey{
    SigningKey(SigningKeyType),
    // SessionTicket(SessionTicket),
}

pub struct KeyStoreEntry {
    id: u128,
    key: SecretKey,
}

impl KeyStoreEntry {
    pub fn new(id: u128, key: SecretKey) -> Self {
        Self{id: id, key: key}
    }
}

struct KeyStore {
    entries: Vec<KeyStoreEntry>,
}

impl KeyStore {
    fn new() -> Self{
        KeyStore{entries: Vec::new()}
    }
    
    fn sign_for_id(&self, id: u128, message: &[u8], params: Option<SigInfo>, rng: &mut impl CryptoRng) -> Result<Signature, Error> {
        self.entries
            .iter()
            .find_map(|entry| match &entry.key {
                SecretKey::SigningKey(key) if entry.id == id => Some(key),
                _ => None,
            }).ok_or(Error::InvalidKey)?
            .sign(message, params, rng)
    }
    
    fn add_entry(&mut self, entry: KeyStoreEntry) {
        self.entries.push(entry);
    }
}

pub fn sign_for_id(id: u128, message: &[u8], params: Option<SigInfo>, rng: &mut impl CryptoRng) -> Result<Signature, Error>{
    let store = KEY_STORE.read().unwrap();
    store.sign_for_id(id, message, params, rng)
}

pub fn add_entry(entry: KeyStoreEntry) {
    let mut store = KEY_STORE.write().unwrap();
    store.add_entry(entry)
}
