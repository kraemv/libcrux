use crate::std::vec::Vec;
use crate::std::boxed::Box;
use std::sync::LazyLock;
use crate::signature::{Error, Signature, SigningKey, SigInfo};

enum SecretKey{
    SigningKey(Box<dyn SigningKey>),
    // KxStaticKey(Box<dyn KxStaticKey>),
}

struct KeyStoreEntry {
    id: u32,
    key: SecretKey,
}

struct KeyStore {
    entries: Vec<KeyStoreEntry>,
}

impl KeyStore {
    pub fn new() -> Self{
        KeyStore{entries: Vec::new()}
    }
    
    fn sign_for_id(&self, id: u32, message: &[u8], params: Option<SigInfo>) -> Result<Signature, Error> {
        let key: &dyn SigningKey = self.entries
                    .iter()
                    .find_map(|entry| match &entry.key {
                        SecretKey::SigningKey(key) if entry.id == id => Some(key),
                        _ => None,
                    }).ok_or(Error::InvalidKey)?.as_ref();
                    
        Ok(key.sign(message, params))
    }
    
    fn add_entry(&mut self, entry: KeyStoreEntry) {
        self.entries.push(entry);
    }
}

static KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| KeyStore::new());
