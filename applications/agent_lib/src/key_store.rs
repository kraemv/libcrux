use crate::hkdf::*;
use crate::hmac::HmacSha256Key;
use crate::hmac::HmacSha256Mac;
use crate::kx::*;
use crate::signatures::{EcDsaP256PublicKey, EcDsaP256PrivateKey, EcDsaP256Signature, Ed25519PublicKey, Ed25519Signature, Ed25519PrivateKey, SHA256};
use crate::ID_SIZE;
use crate::{Error, ID};

use hex;
use libcrux_chacha20poly1305 as chacha20;
use libcrux_curve25519 as curve25519;
use libcrux_curve25519::ecdh_api::EcdhOwned;
use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_kmac as kmac;
use libcrux_ml_kem::mlkem768::{self, MlKem768PrivateKey};
use rand::CryptoRng;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::format;
use std::fs;
use std::mem;
use std::path::Path;
use std::sync::RwLockWriteGuard;
use std::sync::{Arc, RwLock};

const ECDSA_P256_LABEL: &[u8; 12] = b"EcDsaP256Key";
const ED25519_LABEL: &[u8; 10] = b"Ed25519Key";
const MLKEM_768_LABEL: &[u8; 11] = b"MlKem768Key";
const RANDOM_BYTES_LABEL: &[u8; 11] = b"RandomBytes";
const PRK_LABEL: &[u8; 25] = b"HkdfSha256PseudorandomKey";
const SHARED_KEY_LABEL: &[u8; 9] = b"SharedKey";
const X25519_LABEL: &[u8; 9] = b"X25519Key";

pub type EphemeralKeyStore = KeyStore<EphemeralKey>;
pub type LongTermKeyStore = KeyStore<LongTermKey>;

type EcDsaPrivateKey = EcDsaP256PrivateKey<SHA256>;
type LockedEphemeralKeys<'a> = RwLockWriteGuard<'a, HashMap<ID, EphemeralKey>>;
pub enum EphemeralKey {
    ChaCha20Poly1305(chacha20::Key),
    MlKem768(Arc<MlKem768PrivateKey>),
    X25519(X25519SecretKey),
    SharedSecret(SharedKey),
    HkdfSalt(RandomBytes),
    HmacSha256(HmacSha256Key),
    HkdfSha256(HkdfSha256PRK),
    RandomBytes(RandomBytes),
}

pub enum LongTermKey {
    EcDsaP256(EcDsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

impl EphemeralKey {
    pub(crate) fn set_hkdf_salt(&mut self) -> Option<Self> {
        match &self {
            EphemeralKey::RandomBytes(bytes) => {
                let salt_copy = EphemeralKey::HkdfSalt(bytes.clone());
                Some(mem::replace(self, salt_copy))
            }
            _ => None,
        }
    }

    pub(crate) fn set_prk(&mut self) -> Option<Self> {
        let EphemeralKey::RandomBytes(bytes) = self else{None?};
        let key: [u8; 32] = *bytes.as_ref().as_array()?;
        let key = EphemeralKey::HkdfSha256(HkdfSha256PRK::new(key));
        Some(mem::replace(self, key))
    }

    pub(crate) fn set_hmac256_key(&mut self) -> Option<Self> {
        match &self {
            EphemeralKey::RandomBytes(bytes) => {
                let key_copy = EphemeralKey::HmacSha256(bytes.into());
                Some(mem::replace(self, key_copy))
            }
            _ => None,
        }
    }

    pub(crate) fn set_chacha20poly1305_key(&mut self) -> Option<Self> {
        match &self {
            EphemeralKey::RandomBytes(bytes) => {
                let bytes: [u8; chacha20::KEY_LEN] = *bytes.as_ref().as_array()?;
                let key = chacha20::Key::from(bytes);
                let key_copy = EphemeralKey::ChaCha20Poly1305(key);
                Some(mem::replace(self, key_copy))
            }
            _ => None,
        }
    }
}

pub struct KeyStore<KeyType> {
    root_key: [u8; 32],
    entries: RwLock<HashMap<ID, KeyType>>,
}

impl<KeyType> KeyStore<KeyType> {
    fn add_key(&self, id: ID, entry: KeyType) -> Result<(), Error> {
        self.entries
            .write()?
            .insert(id, entry);
        Ok(())
    }

    fn get_id(&self, bytes: &[u8], label: &[u8]) -> Result<ID, Error> {
        kmac::kmac_128(&mut [0u8; ID_SIZE], &self.root_key, bytes, label)
            .try_into()
            .map_err(|_| Error::MAC)
    }
}

fn remove_shared_secret(entries: &mut LockedEphemeralKeys, id: &ID)
-> Result<EphemeralKey, Error> {
    let key = entries.get(id).ok_or(Error::UnknownID)?;
    let EphemeralKey::SharedSecret(_) = key else {Err(Error::Unsupported)?};
    entries.remove(id).ok_or(Error::UnknownID)
}

impl KeyStore<EphemeralKey> {
    pub fn new(rng: &mut impl CryptoRng) -> Result<Self, Error> {
        let mut root_key = [0u8; 32];
        rng.fill_bytes(&mut root_key);
        let entries = RwLock::new(HashMap::new());
        Ok(Self { root_key, entries })
    }

    pub fn chacha20poly1305_decrypt_for_id<'a>(
        &self,
        id: &ID,
        plaintext: &'a mut [u8],
        nonce: &[u8; chacha20::NONCE_LEN],
        tag: &[u8; chacha20::TAG_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], Error> {
        let mut entries = self.entries.write()?;
        match entries.entry(id.clone()) {
            Entry::Occupied(mut entry) => {
                let key = entry.get_mut();
                if matches!(key, EphemeralKey::RandomBytes(_)) {key.set_chacha20poly1305_key().ok_or(Error::Unsupported)?;}
                match key {
                    EphemeralKey::ChaCha20Poly1305(key) => {
                        key.decrypt(plaintext, nonce.into(), aad, ciphertext, tag.into())
                            .map_err(|_| Error::AEAD)?;
                        Ok(plaintext)
                    }
                    _ => Err(Error::Unsupported),
                }
            }
            Entry::Vacant(_) => Err(Error::UnknownID),
        }
    }

    pub fn chacha20poly1305_encrypt_for_id<'a>(
        &self,
        id: &ID,
        ciphertext: &'a mut [u8],
        nonce: &[u8; chacha20::NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(&'a [u8], [u8; chacha20::TAG_LEN]), Error> {
        let mut entries = self.entries.write()?;
        match entries.entry(id.clone()) {
            Entry::Occupied(mut entry) => {
                let key = entry.get_mut();
                if matches!(key, EphemeralKey::RandomBytes(_)) {key.set_chacha20poly1305_key().ok_or(Error::Unsupported)?;}
                let mut tag = chacha20::Tag::from([0u8; chacha20::TAG_LEN]);
                match key {
                    EphemeralKey::ChaCha20Poly1305(key) => {
                        key.encrypt(ciphertext, &mut tag, nonce.into(), aad, plaintext)
                            .map_err(|_| Error::AEAD)?;
                        Ok((ciphertext, *tag.as_ref()))
                    }
                    _ => Err(Error::Unsupported),
                }
            }
            Entry::Vacant(_) => Err(Error::UnknownID),
        }
    }

    pub fn x25519_derive_for_id(&self, id: &ID, pk: &X25519PublicKey) -> Result<ID, Error> {
        let shared_key = {
            let entries = self.entries.read()?;
            match entries.get(id).ok_or(Error::UnknownID)? {
                EphemeralKey::X25519(key) => key.derive(pk),
                _ => Err(Error::Unsupported),
            }?
        };
        let id = self.get_id(shared_key.as_ref(), SHARED_KEY_LABEL)?;
        self.add_key(id.clone(), EphemeralKey::SharedSecret(shared_key))
            .map(|_| id)
    }

    pub fn mlkem_768_decaps_for_id(
        &self,
        id: &ID,
        ct: mlkem768::MlKem768Ciphertext,
    ) -> Result<ID, Error> {
        let shared_key = {
            let entries = self.entries.read()?;
            match entries.get(id).ok_or(Error::UnknownID)? {
                EphemeralKey::MlKem768(key) => Ok(SharedKey::new(mlkem768::decapsulate(key, &ct))),
                _ => Err(Error::Unsupported),
            }?
        };

        let id = self.get_id(shared_key.as_ref(), SHARED_KEY_LABEL)?;
        self.add_key(id.clone(), EphemeralKey::SharedSecret(shared_key))
            .map(|_| id)
    }

    pub fn mlkem_768_encaps_for_id(
        &self,
        pk: &MlKem768PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(ID, MlKem768Ciphertext), Error> {
        let (ct, shared_key) = pk.encaps(rng);
        let id = self.get_id(shared_key.as_ref(), SHARED_KEY_LABEL)?;
        self.add_key(id.clone(), EphemeralKey::SharedSecret(shared_key))
            .map(|_| (id, ct))
    }

    pub fn mlkem_768_generate_key(
        &self,
        rng: &mut impl CryptoRng,
    ) -> Result<(ID, MlKem768PublicKey), Error> {
        let mut rand = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut rand);
        let (sk, pk) = mlkem768::generate_key_pair(rand).into_parts();

        let id = self.get_id(sk.as_slice(), MLKEM_768_LABEL)?;
        let key = EphemeralKey::MlKem768(Arc::new(sk));
        let pk = MlKem768PublicKey::new(pk.into());
        self.add_key(id.clone(), key).map(|_| (id, pk))
    }

    pub fn x25519_generate_key(
        &self,
        rng: &mut impl CryptoRng,
    ) -> Result<(ID, X25519PublicKey), Error> {
        let mut rand = [0u8; curve25519::DK_LEN];
        rng.fill_bytes(&mut rand);
        let (pub_key, priv_key) = curve25519::X25519::generate_pair(&rand)?;

        let id = self.get_id(&priv_key, X25519_LABEL)?;
        let key = EphemeralKey::X25519(X25519SecretKey::new(priv_key));
        let pk = X25519PublicKey::new(pub_key);
        self.add_key(id.clone(), key).map(|_| (id, pk))
    }

    // ------------------------------------------------
    // HKDF
    // ------------------------------------------------
    pub fn sha256_hkdf_extract_public_salt(&self, id: &ID, salt: &[u8])
    -> Result<ID, Error> {
        let key = {remove_shared_secret(&mut self.entries.write()?, id)?};

        let EphemeralKey::SharedSecret(key)= key else {Err(Error::Unsupported)?};
        let pseudorandom_key = key.sha2_256_extract(Some(salt))?;

        let id = self.get_id(pseudorandom_key.as_ref(), PRK_LABEL)?;
        let key = EphemeralKey::HkdfSha256(pseudorandom_key);
        self.add_key(id.clone(), key).map(|_| id)
    }

    pub fn sha256_hkdf_extract_secret_salt(&self, id: Option<&ID>, salt: &ID)
    -> Result<ID, Error> {
        let pseudorandom_key = {
            let mut entries = self.entries.write()?;

            let key = match id {
                Some(id) => remove_shared_secret(&mut entries, id)?,
                None => EphemeralKey::SharedSecret(SharedKey::new([0u8; 32])),
            };
            let EphemeralKey::SharedSecret(key)= key else {Err(Error::Unsupported)?};

            let Entry::Occupied(mut entry) = entries.entry(salt.clone()) else
                {Err(Error::UnknownID)?};
            let salt = entry.get_mut();
            if matches!(salt, EphemeralKey::RandomBytes(_))
                {salt.set_hkdf_salt().ok_or(Error::Unsupported)?;}
            let EphemeralKey::HkdfSalt(salt) = salt else {Err(Error::Unsupported)?};

            key.sha2_256_extract(Some(salt.as_ref()))
        }?;

        let id = self.get_id(pseudorandom_key.as_ref(), PRK_LABEL)?;
        let key = EphemeralKey::HkdfSha256(pseudorandom_key);
        self.add_key(id.clone(), key).map(|_| id)
    }

    pub fn sha256_hkdf_expand(&self, id: &ID, info: &[u8], output_len: usize) 
    -> Result<ID, Error> {
        let okm = {
            let mut entries = self.entries.write()?;

            let Entry::Occupied(mut entry) = entries.entry(id.clone()) else
                {Err(Error::UnknownID)?};
            let key = entry.get_mut();
            if matches!(key, EphemeralKey::RandomBytes(_))
                {key.set_prk().ok_or(Error::Unsupported)?;}
            
            let EphemeralKey::HkdfSha256(key) = key else {Err(Error::Unsupported)?};
            key.sha2_256_expand(info, output_len)
        }?;

        let id = self.get_id(okm.as_ref(), RANDOM_BYTES_LABEL)?;
        let key = EphemeralKey::RandomBytes(okm);
        self.add_key(id.clone(), key).map(|_| id)
    }

    pub fn export_nonce(&self, id: &ID) -> Result<[u8; 12], Error> {
        let key = {
            let mut entries = self.entries.write()?;
            entries.remove(id).ok_or(Error::UnknownID)?
        };
        
        let EphemeralKey::RandomBytes(bytes) = key else {Err(Error::Unsupported)?};
        bytes.as_ref().try_into().map_err(|_| Error::Unsupported)
    }

    pub fn hmac_sha2_256_authenticate(
        &self,
        id: &ID,
        message: &[u8],
    ) -> Result<HmacSha256Mac, Error> {
        let mut entries = self.entries.write()?;
        match entries.entry(id.clone()) {
            Entry::Occupied(mut entry) => {
                let key = entry.get_mut();
                if matches!(key, EphemeralKey::RandomBytes(_)) {key.set_hmac256_key().ok_or(Error::Unsupported)?;}
                match key {
                    EphemeralKey::HmacSha256(key) => Ok(key.authenticate_msg(message)),
                    _ => Err(Error::Unsupported),
                }
            }
            Entry::Vacant(_) => Err(Error::UnknownID),
        }
    }
}

impl KeyStore<LongTermKey> {
    pub fn from_disk() -> Result<Self, Error> {
        let agent_path = format!("{}/agent_dir", env!("HOME"));
        let agent_path = Path::new(&agent_path);
        let root_file = agent_path.join("root_file");

        let file_contents = fs::read(root_file).expect("Cannot read agent file");
        let mut lines = file_contents.split(|c| *c == b'\n');
        let root_key = *lines
            .next()
            .map(|key| hex::decode(key).unwrap())
            .ok_or(Error::Encoding)?
            .as_array()
            .ok_or(Error::Encoding)?;

        let store = Self {
            root_key,
            entries: RwLock::new(HashMap::new()),
        };

        for line in lines {
            let mut parts = line.split(|c| *c == b' ');
            let scheme = parts.next().ok_or(Error::Encoding)?;
            let id: [u8; 31] = *parts
                .next()
                .map(|enc_id: &[u8]| hex::decode(enc_id).unwrap())
                .ok_or(Error::Encoding)?
                .as_array()
                .ok_or(Error::Encoding)?;

            if parts.next().is_some() {
                continue;
            }

            let enc_id = hex::encode(id.as_ref());
            let key_file = agent_path.join(&enc_id[..2]).join(enc_id);

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
                    store.ecdsa_p256_add_key(ecdsa_key).map(|(id, _)| id)
                }
                b"ED_25519" => {
                    let secret_scalar: [u8; 32] = *key_bytes
                        .as_array()
                        .ok_or( Error::Encoding)?;
                    let private_key =
                        Ed25519PrivateKey::new(ed25519::SigningKey::from_bytes(secret_scalar));
                    store.ed25519_add_key(private_key).map(|(id, _)| id)
                }
                _ => return Err(Error::Unsupported),
            };
            if key.is_err() {
                continue;
            }
        }

        Ok(store)
    }

    pub fn ecdsa_p256_sign_for_id(
        &self,
        id: &ID,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<EcDsaP256Signature<SHA256>, Error> {
        let entries = self.entries.read()?;
        match entries.get(id).ok_or(Error::UnknownID)? {
            LongTermKey::EcDsaP256(key) => key.sign(message, rng),
            _ => Err(Error::Unsupported),
        }
    }

    pub fn ed25519_sign_for_id(&self, id: &ID, message: &[u8]) -> Result<Ed25519Signature, Error> {
        let entries = self.entries.read()?;
        let LongTermKey::Ed25519(key) = entries.get(id).ok_or(Error::UnknownID)?
            else {Err(Error::Unsupported)?};
        key.sign(message)
    }

    pub fn ecdsa_p256_add_key(
        &self,
        key: EcDsaP256PrivateKey<SHA256>,
    ) -> Result<(ID, EcDsaP256PublicKey<SHA256>), Error> {
        let id = self.get_id(key.as_bytes(), ECDSA_P256_LABEL)?;

        let pk = ecdsa::p256::secret_to_public(key.get_key()).map_err(|_| Error::PublicKey)?;
        let pk = EcDsaP256PublicKey::<SHA256>::from(pk);

        self.add_key(id.clone(), LongTermKey::EcDsaP256(key))
            .map(|_| (id, pk))
    }

    pub fn ed25519_add_key(&self, key: Ed25519PrivateKey) -> Result<(ID, Ed25519PublicKey), Error> {
        let id = self.get_id(key.as_bytes(), ED25519_LABEL)?;
        let mut pk = [0u8; 32];
        ed25519::secret_to_public(&mut pk, key.as_bytes());

        let pk = Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(pk));

        self.add_key(id.clone(), LongTermKey::Ed25519(key))
            .map(|_| (id, pk))
    }
}
