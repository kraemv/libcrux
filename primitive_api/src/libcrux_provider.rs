use rand_chacha::ChaChaRng;
use rand_chacha::rand_core::SeedableRng;
use libcrux_ecdsa::p256 as p256;
use libcrux_ecdsa::DigestAlgorithm;
use libcrux_ed25519 as ed25519;
use crate::signature::EcDsaP256;
use crate::signature::SigningKey;
use crate::signature::VerificationKey;
use crate::signature::{Ed25519, Error, Signature, VerificationKeyType};
use libcrux_agent::signatures::{EcDsaP256Signature, Ed25519Signature, Ed25519PublicKey};

/*pub enum SigningKeyType {
    Ed25519(libcrux_ed25519::SigningKey, libcrux_ed25519::VerificationKey),
    EcDsaP256(libcrux_ecdsa::p256::PrivateKey, libcrux_ecdsa::p256::PublicKey)
}*/

impl SigningKey<Ed25519> for libcrux_ed25519::SigningKey {
    type PublicKey = libcrux_ed25519::VerificationKey;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        let mut rng = ChaChaRng::from_os_rng();
        ed25519::generate_key_pair(&mut rng)
            .map_err(|_| Error::KeyGenError)
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature, Error> {
        ed25519::sign(payload, self.as_ref())
            .map_err(|_| Error::SigningError)
            .map(|sig| Signature::Ed25519(Ed25519Signature::new(sig)))
            .map_err(|_| Error::InternalError("Agent signing failed".into()))
    }

    fn to_public(&self) -> &Self::PublicKey {
        todo!()
    }
}

impl VerificationKey<Ed25519> for libcrux_ed25519::VerificationKey {
    type VerificationError = libcrux_ed25519::Error;
    type Signature = libcrux_agent::signatures::Ed25519Signature;

    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Self::VerificationError> {
        ed25519::verify(payload, &self.into_bytes(), signature.get_signature())
        
    }
}

impl VerificationKey<EcDsaP256> for p256::PublicKey {
    type VerificationError = libcrux_ecdsa::Error;
    type Signature = libcrux_agent::signatures::EcDsaP256Signature;

    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Self::VerificationError> {
        p256::verify(DigestAlgorithm::Sha256, payload, &signature.get_signature(), self)
        
    }
}