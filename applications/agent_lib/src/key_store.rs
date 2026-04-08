// use crate::signature::{DigestAlgorithm, EcDsaP256PrivKey, EcDsaP256PrivateKey, Error, Signature, SigningKey, SigningKeyType, VerificationKeyType};
use crate::signatures::*;
use crate::kx::*;
use crate::Error;
use crate::ID;

use base64ct::{Base64, Encoding};
use libcrux_curve25519::ecdh_api::EcdhOwned;
use libcrux_curve25519 as curve25519;
use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_ml_kem::mlkem768 as mlkem768;
use libcrux_kmac as kmac;
use libcrux_sha2::Algorithm as DigestAlgorithm;
use rand::CryptoRng;
use std::collections::HashMap;
use std::fmt::Write as fmtWrite;
use std::format;
use std::fs;
use std::path::Path;
use std::string::String;
use std::sync::RwLock;

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub enum SecretKey {
    EcDsaP256Key(EcDsaP256PrivateKey),
    Ed25519Key(Ed25519PrivateKey),
    // SessionTicket(SessionTicket),
    MlKem768Key(mlkem768::MlKem768PrivateKey),
    X25519Key(X25519SecretKey),
    SharedSecret([u8; 32])
}

pub enum PublicKey {
    EcDsaP256Key(EcDsaP256PublicKey),
    Ed25519Key(Ed25519PublicKey),
}

pub struct KeyStoreEntry {
    id: ID,
    key: SecretKey,
}

impl KeyStoreEntry {
    fn new(id: ID, key: SecretKey) -> Self {
        Self { id, key }
    }

    fn get_key(&self) -> &SecretKey {
        &self.key
    }
}

pub struct KeyStore {
    root_key: [u8; 32],
    entries: RwLock<HashMap<ID, KeyStoreEntry>>,
}

impl KeyStore {
    pub fn new(rng: &mut impl CryptoRng) -> Result<Self, Error> {
        let mut root_key = [0u8; 32];
        rng.fill_bytes(&mut root_key);
        let entries = RwLock::new(HashMap::new());
        Ok(Self { root_key, entries })
    }

    pub fn from_disk() -> Result<Self, Error> {
        let agent_path = format!("{}/agent", env!("HOME"));
        let agent_path = Path::new(&agent_path);
        let root_file = agent_path.join("root_file");

        let file_contents = fs::read(root_file).expect("Cannot read agent file");
        let mut lines = file_contents.split(|c| *c == b'\n');
        let mut root_key: [u8; 32] = [0u8; 32];
        lines
            .next()
            .map(|key| Base64::decode(key, &mut root_key).unwrap())
            .ok_or(Error::Encoding)?;

        let store = KeyStore {
            root_key,
            entries: RwLock::new(HashMap::new()),
        };

        for line in lines {
            let mut parts = line.split(|c| *c == b' ');
            let scheme = parts.next().ok_or(Error::Encoding)?;
            let mut id: ID = [0u8; 32];
            parts
                .next()
                .map(|enc_id: &[u8]| Base64::decode(enc_id, &mut id).unwrap())
                .ok_or(Error::Encoding)?;

            if parts.next().is_some() {
                continue;
            }

            let hex_id = encode_hex(&id);

            let mut key_path = String::with_capacity(3);
            write!(&mut key_path, "{:02x}/", id[0]).unwrap();
            let key_file = agent_path.join(key_path).join(hex_id);

            let key_bytes = fs::read(key_file);
            if key_bytes.is_err() {
                continue;
            }
            let key_bytes = key_bytes.unwrap();

            let key = match scheme {
                b"ECDSA_NISTP256_SHA256" => {
                    let private_key = ecdsa::p256::PrivateKey::try_from(key_bytes.as_slice())
                        .map_err(|_| Error::Encoding)?;
                    let ecdsa_key = EcDsaP256PrivateKey::new(private_key, DigestAlgorithm::Sha256);
                    store
                        .add_ecdsa_p256_key(ecdsa_key)
                        .map(|(id, key)| (id, PublicKey::EcDsaP256Key(key)))
                }
                b"ED_25519" => {
                    let secret_scalar: [u8; 32] = key_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Encoding)?;
                    let private_key =
                        Ed25519PrivateKey::new(ed25519::SigningKey::from_bytes(secret_scalar));
                    store
                        .add_ed25519_key(private_key)
                        .map(|(id, key)| (id, PublicKey::Ed25519Key(key)))
                }
                _ => return Err(Error::Unsupported),
            };
            if key.is_err() {
                continue;
            }
        }

        Ok(store)
    }

    fn add_entry(&self, entry: KeyStoreEntry) {
        self.entries.write().unwrap().insert(entry.id, entry);
    }

    fn get_tag(&self, bytes: &[u8], customization: &[u8]) -> Result<ID, Error> {
        let mut tag = [0u8; 32];
        let tag = kmac::kmac_128(&mut tag, &self.root_key, bytes, customization)
            .try_into()
            .unwrap();

        {
            if self.entries.read().unwrap().contains_key(&tag) {
                return Err(Error::DuplicateKey);
            }
        }

        Ok(tag)
    }

    pub fn derive_for_x25519_id(&self, id: ID, pk: &X25519PublicKey) -> Result<ID, Error> {
        let entries = self.entries.read().map_err(|_| Error::Derive)?;
        let shared_key = match entries.get(&id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::X25519Key(key) => key.derive(pk),
            _ => Err(Error::Derive),
        }?;

        let tag = self.get_tag(shared_key.as_bytes(), b"SharedSecret")?;
        let entry = KeyStoreEntry::new(tag, SecretKey::SharedSecret(*shared_key.as_bytes()));
        self.add_entry(entry);

        Ok(tag)
    }

    pub fn decaps_for_mlkem768_id(&self, id: ID, ct: &mlkem768::MlKem768Ciphertext) -> Result<ID, Error> {
        let entries = self.entries.read().map_err(|_| Error::Derive)?;
        let shared_key = match entries.get(&id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::MlKem768Key(key) => Ok(mlkem768::decapsulate(key, ct)),
            _ => Err(Error::Derive),
        }?;

        let tag = self.get_tag(shared_key.as_slice(), b"SharedSecret")?;
        let entry = KeyStoreEntry::new(tag, SecretKey::SharedSecret(shared_key));
        self.add_entry(entry);

        Ok(tag)
    }

    pub fn encaps_for_mlkem768_id(&self, pk: &mlkem768::MlKem768PublicKey, rng: &mut impl CryptoRng) -> Result<(ID, mlkem768::MlKem768Ciphertext), Error> {
        let mut rand = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut rand);
        let (ct, shared_key) = mlkem768::encapsulate(pk, rand);

        let tag = self.get_tag(shared_key.as_slice(), b"SharedSecret")?;
        let entry = KeyStoreEntry::new(tag, SecretKey::SharedSecret(shared_key));
        self.add_entry(entry);

        Ok((tag, ct))
    }

    pub fn export_shared_secret(&self, id: ID) -> Result<[u8; 32], Error> {
        let entries = self.entries.read().map_err(|_| Error::Derive)?;
        match entries.get(&id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::SharedSecret(key) => Ok(*key),
            _ => Err(Error::Derive),
        }
    }

    pub fn sign_for_ecdsa_p256_id(
        &self,
        id: ID,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<EcDsaP256Signature, Error> {
        let entries = self.entries.read().map_err(|_| Error::Signing)?;
        match entries.get(&id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::EcDsaP256Key(key) => key.sign(message, rng),
            _ => Err(Error::Signing),
        }
    }

    pub fn sign_for_ed25519_id(
        &self,
        id: ID,
        message: &[u8],
    ) -> Result<Ed25519Signature, Error> {
        let entries = self.entries.read().map_err(|_| Error::Signing)?;
        match entries.get(&id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::Ed25519Key(key) => key.sign(message),
            _ => Err(Error::Signing),
        }
    }

    pub fn add_ecdsa_p256_key(
        &self,
        key: EcDsaP256PrivateKey,
    ) -> Result<(ID, EcDsaP256PublicKey), Error> {
        let tag = self.get_tag(key.as_bytes(), b"EcDsaP256Key")?;

        let pk = ecdsa::p256::secret_to_public(key.get_key()).map_err(|_| Error::PublicKey)?;
        let pk = EcDsaP256PublicKey::new(pk, key.get_alg());

        let entry = KeyStoreEntry::new(tag, SecretKey::EcDsaP256Key(key));
        self.add_entry(entry);

        Ok((tag, pk))
    }

    pub fn add_ed25519_key(
        &self,
        key: Ed25519PrivateKey,
    ) -> Result<(ID, Ed25519PublicKey), Error> {
        let tag = self.get_tag(key.as_bytes(), b"Ed25519Key")?;
        let mut pk = [0u8; 32];
        ed25519::secret_to_public(&mut pk, key.as_bytes());

        let pk = Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(pk));

        let entry = KeyStoreEntry::new(tag, SecretKey::Ed25519Key(key));
        self.add_entry(entry);

        Ok((tag, pk))
    }

    pub fn generate_mlkem_768_key(&self, rng: &mut impl CryptoRng) -> Result<(ID, MlKem768PublicKey), Error> {
        let mut rand = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut rand);
        let key_pair = mlkem768::generate_key_pair(rand);

        let id = self.get_tag(key_pair.private_key().as_slice(), b"MlKem768Key")?;
        let key = SecretKey::MlKem768Key(key_pair.private_key().clone());
        let pk = MlKem768PublicKey::new(*key_pair.public_key().as_slice());
        let entry = KeyStoreEntry { id, key };
        self.add_entry(entry);

        Ok((id, pk))
    }
    
    pub fn generate_x25519_key(&self, rng: &mut impl CryptoRng) -> Result<(ID, X25519PublicKey), Error> {
        let mut rand = [0u8; curve25519::DK_LEN];
        rng.fill_bytes(&mut rand);
        let (pub_key, priv_key) = curve25519::X25519::generate_pair(&rand).map_err(|_| Error::KeyExchange)?;

        let id = self.get_tag(&priv_key, b"X25519Key")?;
        let key = SecretKey::X25519Key(X25519SecretKey::new(priv_key));
        let pk = X25519PublicKey::new(pub_key);
        let entry = KeyStoreEntry { id, key };
        self.add_entry(entry);

        Ok((id, pk))
    }
}
