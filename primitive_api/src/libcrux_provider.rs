use libcrux_agent::signatures;
use rand_chacha::ChaChaRng;
use rand_chacha::rand_core::SeedableRng;
use libcrux_ecdsa::p256 as p256;
use libcrux_ecdsa::DigestAlgorithm;
use libcrux_ed25519 as ed25519;
use crate::signature::SigningKey;
use crate::signature::VerificationKey;
use crate::signature::Error;
use libcrux_agent::signatures::Ed25519Signature;

pub struct Ed25519SigningKey(libcrux_ed25519::SigningKey);

impl SigningKey<64> for Ed25519SigningKey {
    type PublicKey = libcrux_ed25519::VerificationKey;
    type Signature = signatures::Ed25519Signature;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let mut rng = ChaChaRng::from_os_rng();
        ed25519::generate_key_pair(&mut rng)
            .map(|(sk, vk)| (Ed25519SigningKey(sk), vk))
            .map_err(|_| Error::KeyGenError)
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        ed25519::sign(payload, self.0.as_ref())
            .map_err(|_| Error::SigningError)
            .map(Ed25519Signature::new)
    }

    fn to_public(&self) -> &Self::PublicKey {
        todo!()
    }

    fn scheme(&self) -> crate::signature::SignatureScheme {
        crate::signature::SignatureScheme::Ed25519
    }
}

impl Ed25519SigningKey {
    pub fn new(sk: libcrux_ed25519::SigningKey) -> Self {
        Self(sk)
    }
}
impl VerificationKey for libcrux_ed25519::VerificationKey {
    type Signature = libcrux_agent::signatures::Ed25519Signature;

    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Error> {
        ed25519::verify(payload, &self.into_bytes(), signature.get_signature())
            .map_err(Error::from)
    }
}

impl VerificationKey for p256::PublicKey {
    type Signature = libcrux_agent::signatures::EcDsaP256Signature;

    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Error> {
        p256::verify(DigestAlgorithm::Sha256, payload, &signature.get_signature(), self)
            .map_err(Error::from)
    }
}