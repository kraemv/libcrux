use crate::hkdf::*;
use crate::hmac::HmacSha256Key;
use crate::hmac::HmacSha256Mac;
use crate::kx::*;
use crate::signatures::*;
use crate::{Error, ID};

use base64ct::{Base64, Encoding};
use hex;
use std::collections::hash_map::Entry;
use std::mem;
use std::vec::Vec as std_vec;
use libcrux_curve25519 as curve25519;
use libcrux_curve25519::ecdh_api::EcdhOwned;
use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_kmac as kmac;
use libcrux_ml_kem::mlkem768;
use rand::CryptoRng;
use std::collections::HashMap;
use std::fmt::Write as fmtWrite;
use std::format;
use std::fs;
use std::path::Path;
use std::string::String;
use std::sync::{Arc, RwLock};


const ECDSA_P256_LABEL: &[u8; 12] = b"EcDsaP256Key";
const ED25519_LABEL: &[u8; 10] = b"Ed25519Key";
const MLKEM_768_LABEL: &[u8; 11] = b"MlKem768Key";
const RANDOM_BYTES_LABEL: &[u8; 11] = b"RandomBytes";
const PRK_LABEL: &[u8; 15] = b"PseudorandomKey";
const SHARED_KEY_LABEL: &[u8; 9] = b"SharedKey";
const X25519_LABEL: &[u8; 9] = b"X25519Key";

pub(crate) enum SecretKey {
    EcDsaP256Key(EcDsaP256PrivateKey<SHA256>),
    Ed25519Key(Ed25519PrivateKey),
    MlKem768Key(Arc<mlkem768::MlKem768PrivateKey>),
    X25519Key(X25519SecretKey),
    SharedSecret(SharedKey),
    HkdfSalt(RandomBytes),
    HMACKey(HmacSha256Key),
    PseudorandomKey(PseudorandomKey),
    RandomBytes(RandomBytes),
}

pub enum PublicKey {
    EcDsaP256Key(EcDsaP256PublicKey<SHA256>),
    Ed25519Key(Ed25519PublicKey),
}

pub struct KeyStoreEntry {
    id: ID,
    key: SecretKey,
}

impl SecretKey {
    pub(crate) fn set_hkdf_salt(&mut self) -> Option<Self> {
        match &self {
            SecretKey::RandomBytes(bytes) |
            SecretKey::HkdfSalt(bytes) => {
                let salt_copy = SecretKey::HkdfSalt(bytes.clone());
                Some(mem::replace(self, salt_copy))
            },
            _ => None,
        }
    }

    pub(crate) fn set_hmac256_key(&mut self) -> Option<Self> {
        match &self {
            SecretKey::RandomBytes(bytes) => {
                let key_copy = SecretKey::HMACKey(bytes.into());
                Some(mem::replace(self, key_copy))
            },
            SecretKey::HMACKey(bytes) => {
                let key_copy = SecretKey::HMACKey(bytes.clone());
                Some(mem::replace(self, key_copy))
            },
            _ => None,
        }
    }
}

impl KeyStoreEntry {
    fn new(id: ID, key: SecretKey) -> Self {
        Self { id, key }
    }

    fn get_key(&self) -> &SecretKey {
        &self.key
    }

    fn get_mut_key(&mut self) -> &mut SecretKey {
        &mut self.key
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
            let mut id = [0u8; 32];
            parts
                .next()
                .map(|enc_id: &[u8]| Base64::decode(enc_id, &mut id).unwrap())
                .ok_or(Error::Encoding)?;

            if parts.next().is_some() {
                continue;
            }

            let hex_id = hex::encode(id);

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
                    let ecdsa_key = EcDsaP256PrivateKey::<SHA256>::from(private_key);
                    store
                        .ecdsa_p256_add_key(ecdsa_key)
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
                        .ed25519_add_key(private_key)
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
        self.entries.write().unwrap().insert(entry.id.clone(), entry);
    }

    fn get_tag(&self, bytes: &[u8], customization: &[u8]) -> Result<ID, Error> {
        let mut tag = [0u8; 32];
        let tag = kmac::kmac_128(&mut tag, &self.root_key, bytes, customization)
            .try_into()
            .unwrap();

        /*{
            if self.entries.read().unwrap().contains_key(&tag) {
                return Err(Error::DuplicateKey);
            }
        }*/

        Ok(tag)
    }

    pub fn x25519_derive_for_id(&self, id: &ID, pk: &X25519PublicKey) -> Result<ID, Error> {
        let shared_key = {
            let entries = self.entries.read().map_err(|_| Error::Derive)?;
            match entries.get(id).ok_or(Error::UnknownID)?.get_key() {
                SecretKey::X25519Key(key) => key.derive(pk),
                _ => Err(Error::Derive),
            }?
        };
        let id = self.get_tag(shared_key.as_ref(), SHARED_KEY_LABEL)?;
        let entry = KeyStoreEntry::new(id.clone(), SecretKey::SharedSecret(shared_key));
        self.add_entry(entry);

        Ok(id)
    }

    pub fn mlkem_768_decaps_for_id(
        &self,
        id: &ID,
        ct: mlkem768::MlKem768Ciphertext,
    ) -> Result<ID, Error> {
        let shared_key = {
            let entries = self.entries.read().map_err(|_| Error::Derive)?;
            match entries.get(id).ok_or(Error::UnknownID)?.get_key() {
                SecretKey::MlKem768Key(key) => Ok(SharedKey::new(mlkem768::decapsulate(key, &ct))),
                _ => Err(Error::Derive),
            }?
        };

        let id = self.get_tag(shared_key.as_ref(), SHARED_KEY_LABEL)?;
        let entry = KeyStoreEntry::new(id.clone(), SecretKey::SharedSecret(shared_key));
        self.add_entry(entry);

        Ok(id)
    }

    pub fn mlkem_768_encaps_for_id(
        &self,
        pk: &MlKem768PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(ID, MlKem768Ciphertext), Error> {
        let (ct, shared_key) = pk.encaps(rng);
        let id = self.get_tag(shared_key.as_ref(), SHARED_KEY_LABEL)?;
        let entry = KeyStoreEntry::new(id.clone(), SecretKey::SharedSecret(shared_key));
        self.add_entry(entry);

        Ok((id, ct))
    }

    pub fn export_key_material(&self, id: &ID) -> Result<std_vec<u8>, Error> {
        let entries = self.entries.read().map_err(|_| Error::Derive)?;
        match entries.get(id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::RandomBytes(key) => Ok(key.into_vec()),
            _ => Err(Error::Derive),
        }
    }

    pub fn ecdsa_p256_sign_for_id(
        &self,
        id: &ID,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<EcDsaP256Signature<SHA256>, Error> {
        let entries = self.entries.read().map_err(|_| Error::Signing)?;
        match entries.get(id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::EcDsaP256Key(key) => key.sign(message, rng),
            _ => Err(Error::Signing),
        }
    }

    pub fn ed25519_sign_for_id(&self, id: &ID, message: &[u8]) -> Result<Ed25519Signature, Error> {
        let entries = self.entries.read().map_err(|_| Error::Signing)?;
        match entries.get(id).ok_or(Error::UnknownID)?.get_key() {
            SecretKey::Ed25519Key(key) => key.sign(message),
            _ => Err(Error::Signing),
        }
    }

    pub fn ecdsa_p256_add_key(
        &self,
        key: EcDsaP256PrivateKey<SHA256>,
    ) -> Result<(ID, EcDsaP256PublicKey<SHA256>), Error> {
        let id = self.get_tag(key.as_bytes(), ECDSA_P256_LABEL)?;

        let pk = ecdsa::p256::secret_to_public(key.get_key()).map_err(|_| Error::PublicKey)?;
        let pk = EcDsaP256PublicKey::<SHA256>::from(pk);

        let entry = KeyStoreEntry::new(id.clone(), SecretKey::EcDsaP256Key(key));
        self.add_entry(entry);

        Ok((id, pk))
    }

    pub fn ed25519_add_key(&self, key: Ed25519PrivateKey) -> Result<(ID, Ed25519PublicKey), Error> {
        let id = self.get_tag(key.as_bytes(), ED25519_LABEL)?;
        let mut pk = [0u8; 32];
        ed25519::secret_to_public(&mut pk, key.as_bytes());

        let pk = Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(pk));

        let entry = KeyStoreEntry::new(id.clone(), SecretKey::Ed25519Key(key));
        self.add_entry(entry);

        Ok((id, pk))
    }

    pub fn mlkem_768_generate_key(
        &self,
        rng: &mut impl CryptoRng,
    ) -> Result<(ID, MlKem768PublicKey), Error> {
        let mut rand = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut rand);
        let (sk, pk) = mlkem768::generate_key_pair(rand).into_parts();

        let id = self.get_tag(sk.as_slice(), MLKEM_768_LABEL)?;
        let key = SecretKey::MlKem768Key(Arc::new(sk));
        let pk = MlKem768PublicKey::new(pk.into());
        let entry = KeyStoreEntry { id: id.clone(), key };
        self.add_entry(entry);

        Ok((id, pk))
    }

    pub fn x25519_generate_key(
        &self,
        rng: &mut impl CryptoRng,
    ) -> Result<(ID, X25519PublicKey), Error> {
        let mut rand = [0u8; curve25519::DK_LEN];
        rng.fill_bytes(&mut rand);
        let (pub_key, priv_key) =
            curve25519::X25519::generate_pair(&rand).map_err(|_| Error::KeyExchange)?;

        let id = self.get_tag(&priv_key, X25519_LABEL)?;
        let key = SecretKey::X25519Key(X25519SecretKey::new(priv_key));
        let pk = X25519PublicKey::new(pub_key);
        let entry = KeyStoreEntry { id: id.clone(), key };
        self.add_entry(entry);

        Ok((id, pk))
    }

    // ------------------------------------------------
    // HKDF
    // ------------------------------------------------
    pub fn sha256_hkdf_extract_public_salt(&self, id: &ID, salt: &[u8]) -> Result<ID, Error> {
        let entry = {
                let mut entries = self.entries.write().map_err(|_| Error::HKDF)?;
                entries.remove(id).ok_or(Error::UnknownID)?
        };

        let pseudorandom_key = match entry.get_key() {
            SecretKey::SharedSecret(key) => key.sha2_256_hkdf_extract(Some(salt)),
            _ => Err(Error::HKDF),
        }?;

        let id = self.get_tag(pseudorandom_key.as_ref(), PRK_LABEL)?;
        let key = SecretKey::PseudorandomKey(pseudorandom_key);
        let entry = KeyStoreEntry { id: id.clone(), key };
        self.add_entry(entry);

        Ok(id)
    }

    pub fn sha256_hkdf_extract_secret_salt(&self, id: Option<&ID>, salt: &ID) -> Result<ID, Error> {
        let (key_entry, salt_value) = {
            let mut entries = self.entries.write().map_err(|_| Error::HKDF)?;

            let key_entry = match id {
                Some(id) => {
                    entries.remove(id).ok_or(Error::UnknownID)?
                }
                None => {
                    let default_key = SecretKey::SharedSecret(SharedKey::new([0u8; 32]));
                    KeyStoreEntry::new(ID::from([0u8; 32]), default_key)
                }
            };
            
            let salt_entry = match entries.entry(salt.clone()) {
                Entry::Occupied(mut entry) => {
                    let entry = entry.get_mut();
                    entry.get_mut_key().set_hkdf_salt().ok_or(Error::HKDF)
                }
                Entry::Vacant(_) => Err(Error::UnknownID),
            }?;

            (key_entry, salt_entry)
        };

        
        let pseudorandom_key = match (key_entry.get_key(), salt_value) {
            (SecretKey::SharedSecret(key), SecretKey::HkdfSalt(salt)) | 
            (SecretKey::SharedSecret(key), SecretKey::RandomBytes(salt)) => key.sha2_256_hkdf_extract(Some(salt.as_ref())),
            _ => Err(Error::HKDF),
        }?;


        let id = self.get_tag(pseudorandom_key.as_ref(), PRK_LABEL)?;
        let key = SecretKey::PseudorandomKey(pseudorandom_key);
        let entry = KeyStoreEntry::new(id.clone(), key );
        self.add_entry(entry);

        Ok(id)
    }

    pub fn sha256_hkdf_expand(&self, id: &ID, info: &[u8], output_len: usize) -> Result<ID, Error> {
        let out_key_material = {
            let entries = self.entries.read().map_err(|_| Error::Derive)?;
            match entries.get(id).ok_or(Error::UnknownID)?.get_key() {
                SecretKey::PseudorandomKey(key) => key.sha2_256_hkdf_expand(info, output_len),
                _ => Err(Error::Derive),
            }?
        };

        let id = self.get_tag(out_key_material.as_ref(), RANDOM_BYTES_LABEL)?;
        let key = SecretKey::RandomBytes(out_key_material);
        let entry = KeyStoreEntry { id: id.clone(), key };
        self.add_entry(entry);

        Ok(id)
    }

    pub fn hmac_sha2_256_authenticate(&self, id: &ID, message: &[u8]) -> Result<HmacSha256Mac, Error> {
        let mut entries = self.entries.write().map_err(|_| Error::MAC)?;
        match entries.entry(id.clone()) {
            Entry::Occupied(mut entry) => {
                let entry = entry.get_mut();
                entry.get_mut_key().set_hmac256_key().ok_or(Error::MAC)?;
                match entry.get_key() {
                    SecretKey::HMACKey(key) => Ok(key.authenticate(message)),
                    _ => Err(Error::MAC),
                }
            }
            Entry::Vacant(_) => Err(Error::UnknownID),
        }
    }
}