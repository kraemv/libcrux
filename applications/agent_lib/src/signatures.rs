use crate::Error;
use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_sha2::Algorithm as DigestAlgorithm;
use rand::CryptoRng;

// A signature that holds its actual value and additional information
pub struct EcDsaP256Signature {
    sig: ecdsa::p256::Signature,
    alg: DigestAlgorithm,
}

pub struct EcDsaP256PublicKey{
    key: ecdsa::p256::PublicKey,
    alg: DigestAlgorithm,
}

pub struct EcDsaP256PrivateKey{
    key: ecdsa::p256::PrivateKey,
    alg: DigestAlgorithm,
}

pub struct Ed25519PrivateKey(ed25519::SigningKey);

pub struct Ed25519PublicKey(ed25519::VerificationKey);

pub struct Ed25519Signature(ed25519::Signature);

impl EcDsaP256Signature {
    pub fn new(sig: ecdsa::p256::Signature, alg: DigestAlgorithm) -> Self {
        Self { sig, alg }
    }
    
    pub fn get_signature(&self) -> ecdsa::p256::Signature {
        self.sig
    }

    pub fn get_alg(&self) -> DigestAlgorithm{
        self.alg
    }
}

impl EcDsaP256PublicKey {
    pub fn new(key: ecdsa::p256::PublicKey, alg: DigestAlgorithm) -> Self {
        Self { key, alg }
    }

    pub fn get_alg(&self) -> DigestAlgorithm {
        self.alg
    }

    pub fn get_key(&self) -> &ecdsa::p256::PublicKey {
        &self.key
    }
}

impl EcDsaP256PrivateKey {
    pub fn new (key: ecdsa::p256::PrivateKey, alg: DigestAlgorithm) -> Self {
        Self {key, alg}
    }

    pub fn sign(&self, message: &[u8], rng: &mut impl CryptoRng) -> Result<EcDsaP256Signature, Error> {
        let nonce = ecdsa::p256::Nonce::random(rng).map_err(|_| Error::Signing)?;
        let sig = ecdsa::p256::sign(self.alg, message, &self.key, &nonce)
            .map_err(|_| Error::Signing)?;
        Ok(EcDsaP256Signature::new(sig, self.alg))
    }

    pub fn get_alg(&self) -> DigestAlgorithm {
        self.alg
    }

    pub fn get_key(&self) -> &ecdsa::p256::PrivateKey {
        &self.key
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_ref()
    }
}

impl Ed25519Signature {
    pub fn new(signature: ed25519::Signature) -> Self {
        Self(signature)
    }

    pub fn into_bytes(self) -> [u8; 64] {
        self.0.into_bytes()
    }
}
impl Ed25519PrivateKey {
    pub fn new (key: ed25519::SigningKey) -> Self {
        Self(key)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, Error> {
        let signature = ed25519::sign(message, self.0.as_ref()).map_err(|_| Error::Signing)?;
        Ok(Ed25519Signature(signature))
    }

    pub fn get_key(&self) -> &ed25519::SigningKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }  
}

impl Ed25519PublicKey {
    pub fn new (key: ed25519::VerificationKey) -> Self {
        Self(key)
    }
    
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.into_bytes()
    }
}