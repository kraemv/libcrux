use std::marker::PhantomData;

use crate::Error;
use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_sha2::Algorithm as DigestAlgorithm;
use rand::CryptoRng;

pub struct EcDsaP256SHA256 {}
pub struct Ed25519 {}

#[derive(Debug)]
pub struct SHA256 {}

// A signature that holds its actual value and additional information
pub struct EcDsaP256Signature<DigestAlg> {
    sig: ecdsa::p256::Signature,
    _marker: PhantomData<DigestAlg>,
}

#[derive(Debug)]
pub struct EcDsaP256PublicKey<DigestAlg> {
    key: ecdsa::p256::PublicKey,
    _marker: PhantomData<DigestAlg>,
}

pub struct EcDsaP256PrivateKey<DigestAlg> {
    key: ecdsa::p256::PrivateKey,
    _marker: PhantomData<DigestAlg>,
}

pub struct Ed25519PrivateKey(ed25519::SigningKey);

#[derive(Clone, Debug)]
pub struct Ed25519PublicKey(ed25519::VerificationKey);

pub struct Ed25519Signature(ed25519::Signature);

impl<DigestAlg> EcDsaP256Signature<DigestAlg> {
    pub fn get_signature(&self) -> ecdsa::p256::Signature {
        self.sig
    }
}

impl EcDsaP256Signature<SHA256> {
    pub fn get_alg(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }
}

impl<Algo> From<ecdsa::p256::Signature> for EcDsaP256Signature<Algo> {
    fn from(sig: ecdsa::p256::Signature) -> Self {
        Self {
            sig,
            _marker: PhantomData,
        }
    }
}

impl<DigestAlg> EcDsaP256PublicKey<DigestAlg> {
    pub fn get_key(&self) -> &ecdsa::p256::PublicKey {
        &self.key
    }
}

impl EcDsaP256PublicKey<SHA256> {
    pub fn get_alg(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }
}

impl<Algo> From<ecdsa::p256::PublicKey> for EcDsaP256PublicKey<Algo> {
    fn from(vk: ecdsa::p256::PublicKey) -> Self {
        Self {
            key: vk,
            _marker: PhantomData,
        }
    }
}

impl Clone for EcDsaP256PublicKey<SHA256> {
    fn clone(&self) -> Self {
        let key = ecdsa::p256::PublicKey::try_from(&self.get_key().0).unwrap();
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl From<ecdsa::p256::PrivateKey> for EcDsaP256PrivateKey<SHA256> {
    fn from(sk: ecdsa::p256::PrivateKey) -> Self {
        Self {
            key: sk,
            _marker: PhantomData,
        }
    }
}

impl<DigestAlg> EcDsaP256PrivateKey<DigestAlg> {
    pub fn get_key(&self) -> &ecdsa::p256::PrivateKey {
        &self.key
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_ref()
    }
}

impl EcDsaP256PrivateKey<SHA256> {
    pub fn sign(
        &self,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<EcDsaP256Signature<SHA256>, Error> {
        let nonce = ecdsa::p256::Nonce::random(rng).map_err(|_| Error::Signing)?;
        let sig = ecdsa::p256::sign(DigestAlgorithm::Sha256, message, &self.key, &nonce)
            .map_err(|_| Error::Signing)?;
        Ok(EcDsaP256Signature::<SHA256>::from(sig))
    }

    pub fn get_alg(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
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

impl<Algo> From<EcDsaP256Signature<Algo>> for [u8; 64] {
    fn from(sig: EcDsaP256Signature<Algo>) -> Self {
        *sig.get_signature().as_bytes()
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes
            .try_into()
            .map(|bytes| Self::new(ed25519::VerificationKey::from_bytes(bytes)))
            .map_err(|_| Error::PublicKey)
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes
            .try_into()
            .map(|bytes| Self::new(ed25519::Signature::from_bytes(bytes)))
            .map_err(|_| Error::Signing)
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Algo> TryFrom<&[u8]> for EcDsaP256PublicKey<Algo> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ecdsa::p256::PublicKey::try_from(bytes)
            .map(Self::from)
            .map_err(|_| Error::PublicKey)
    }
}

impl<Algo> AsRef<[u8]> for EcDsaP256PublicKey<Algo> {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl<Algo> TryFrom<&[u8]> for EcDsaP256Signature<Algo> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes
            .try_into()
            .map(|bytes| Self::from(ecdsa::p256::Signature::from_bytes(bytes)))
            .map_err(|_| Error::Signing)
    }
}

impl<Algo> AsRef<[u8]> for EcDsaP256Signature<Algo> {
    fn as_ref(&self) -> &[u8] {
        self.sig.as_bytes()
    }
}
