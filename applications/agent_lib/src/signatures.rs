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

#[derive(Debug)]
pub struct EcDsaP256PublicKey {
    key: ecdsa::p256::PublicKey,
    alg: DigestAlgorithm,
}

pub struct EcDsaP256PrivateKey {
    key: ecdsa::p256::PrivateKey,
    alg: DigestAlgorithm,
}

pub struct Ed25519PrivateKey(ed25519::SigningKey);

#[derive(Clone, Debug)]
pub struct Ed25519PublicKey(ed25519::VerificationKey);

pub struct Ed25519Signature(ed25519::Signature);

impl EcDsaP256Signature {
    pub fn new(sig: ecdsa::p256::Signature, alg: DigestAlgorithm) -> Self {
        Self { sig, alg }
    }

    pub fn get_signature(&self) -> ecdsa::p256::Signature {
        self.sig
    }

    pub fn get_alg(&self) -> DigestAlgorithm {
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

impl Clone for EcDsaP256PublicKey {
    fn clone(&self) -> Self {
        let key = ecdsa::p256::PublicKey::try_from(&self.get_key().0).unwrap();
        Self {
            key,
            alg: self.get_alg(),
        }
    }
}

impl EcDsaP256PrivateKey {
    pub fn new(key: ecdsa::p256::PrivateKey, alg: DigestAlgorithm) -> Self {
        Self { key, alg }
    }

    pub fn sign(
        &self,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<EcDsaP256Signature, Error> {
        let nonce = ecdsa::p256::Nonce::random(rng).map_err(|_| Error::Signing)?;
        let sig =
            ecdsa::p256::sign(self.alg, message, &self.key, &nonce).map_err(|_| Error::Signing)?;
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

    pub fn as_bytes(&self) -> &[u8; 64] {
        self.0.as_ref()
    }

    pub fn get_signature(&self) -> &ed25519::Signature {
        &self.0
    }
}

impl Ed25519PrivateKey {
    pub fn new(key: ed25519::SigningKey) -> Self {
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
    pub fn new(key: ed25519::VerificationKey) -> Self {
        Self(key)
    }

    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.into_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<Ed25519Signature> for [u8; 64] {
    fn from(sig: Ed25519Signature) -> Self {
        sig.into_bytes()
    }
}

impl From<EcDsaP256Signature> for [u8; 64] {
    fn from(sig: EcDsaP256Signature) -> Self {
        let mut out = [0u8; 64];
        let sig = sig.get_signature();
        let (r,s) = sig.as_bytes();
        out[0..32].copy_from_slice(r);
        out[32..64].copy_from_slice(s);
        out
    }
}