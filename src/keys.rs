use crate::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, Error, Signature, SigningKey, SigningKeyType, VerificationKeyType};
use crate::RNG;
use base64ct::{Base64, Encoding};
use libcrux_kmac as kmac;
use std::format;
use std::fs;
use std::{path::Path};
use std::collections::HashMap;
use std::string::{String};
use std::sync::{LazyLock, RwLock};
use std::fmt::Write as fmtWrite;

static KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

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
        Self { id, key }
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
    fn from_disk() -> Result<Self, Error> {
        let agent_path = format!("{}/agent", env!("HOME"));
        let agent_path = Path::new(&agent_path);
        let root_file = agent_path.join("root_file");

        let file_contents = fs::read(root_file).expect("Cannot read agent file");
        let mut lines = file_contents.split(|c| *c == b'\n');
        let mut root_key: [u8; 32] = [0u8; 32];
        lines
            .next()
            .map(|key| Base64::decode(key, &mut root_key).unwrap())
            .ok_or(Error::InvalidKey)?;

        let store = KeyStore{
            root_key,
            entries: RwLock::new(HashMap::new()),
        };

        for line in lines {
            let mut parts = line.split(|c| *c == b' ');
            let scheme = parts.next().ok_or(Error::InvalidKey)?;
            let mut id: [u8; 32] = [0u8; 32];
            parts
                .next()
                .map(|enc_id: &[u8]| Base64::decode(enc_id, &mut id).unwrap())
                .ok_or(Error::InvalidKey)?;

            if parts.next().is_some()
            { continue; }

            let hex_id = encode_hex(&id);

            let mut key_path = String::with_capacity(3);
            write!(&mut key_path, "{:02x}/", id[0]).unwrap();
            let key_file = agent_path.join(key_path).join(hex_id);

            let key_bytes = fs::read(key_file);
            if key_bytes.is_err() { continue; }
            let key_bytes = key_bytes.unwrap();

            let key = match scheme {
                b"ECDSA_NISTP256_SHA256" => {
                    let ecdsa_key = EcDsaP256PrivKey::new(EcDsaP256PrivateKey::try_from(key_bytes.as_slice()).map_err(|_| Error::InvalidKey)?, DigestAlgorithm::Sha256);
                    SecretKey::SigningKey(SigningKeyType::EcDsaP256(ecdsa_key))
                }
                _ => return Err(Error::InvalidKey),
            };
            if store.add_key(key).is_err() {
                continue;
            }
        }

        Ok(store)


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

    fn add_key(&self, key: SecretKey) -> Result<([u8; 32], VerificationKeyType), Error> {
        let bytes: &[u8] = match &key {
            SecretKey::SigningKey(sig_key) => sig_key.as_ref(),
        };
        let customization: &[u8] = match key {
            SecretKey::SigningKey(SigningKeyType::EcDsaP256(_)) => b"EcDsaP256Key",
            SecretKey::SigningKey(SigningKeyType::Ed25519(_)) => b"Ed25519Key",
        };
        let mut tag = [0u8; 32];
        let tag = kmac::kmac_128(&mut tag, &self.root_key, bytes, customization)
            .try_into()
            .unwrap();
        
        {
            if self.entries.read().unwrap().contains_key(&tag)
            {return Err(Error::InvalidKey);}
        }
        let pk: VerificationKeyType = match &key {
            SecretKey::SigningKey(sig_key) => sig_key.to_public().expect("Public Key creation failed"),
        };
        
        let entry = KeyStoreEntry::new(tag, key);
        self.add_entry(entry);
        
        Ok((tag, pk))
        
}
}

pub fn sign_for_id(id: [u8; 32], message: &[u8]) -> Result<Signature, Error> {
    KEY_STORE.sign_for_id(id, message)
}

pub fn add_entry(entry: KeyStoreEntry) {
    KEY_STORE.add_entry(entry)
}

pub fn add_key(key: SecretKey) -> Result<([u8; 32], VerificationKeyType), Error> {
    KEY_STORE.add_key(key)
}
