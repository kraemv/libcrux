//! # Signatures
//!
//! * EcDSA P256 with Sha256, Sha384, and Sha512
//! * EdDSA 25519

use core::fmt::Debug;
use std::marker::PhantomData;

use crate::NetworkObject;
use crate::provider::get_agent;
use libcrux_agent::signatures::{EcDsaP256PublicKey, Ed25519PublicKey, SHA256};
use libcrux_agent::{signatures, ID};
use libcrux_ecdsa::p256;
use libcrux_ecdsa::DigestAlgorithm;
use libcrux_ed25519 as ed25519;

use der::{Any, Tagged, FixedTag};
use der::oid::Arc as OidArc;
use der::asn1::{BitString, OctetString, SetOfRef};
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use pki_types::PrivatePkcs8KeyDer;
use x509_cert::attr::Attribute;

pub type DefaultSigningKey = libcrux_ed25519::SigningKey;

/// Signature Errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InternalError(String),
    SigningError,
    InvalidSignature,
    KeyGenError,
    InvalidKey,
    InputTooLarge,
    Verify
}

pub trait Sig {}

#[derive(Clone, Debug)]
pub struct Ed25519{}
#[derive(Clone, Debug)]
pub struct EcDsaP256{}

impl Sig for Ed25519 {}
impl Sig for EcDsaP256 {}

impl NetworkObject for EcDsaP256PublicKey<SHA256> { }
impl NetworkObject for signatures::EcDsaP256Signature<SHA256>{ }
impl NetworkObject for Ed25519PublicKey { }
impl NetworkObject for signatures::Ed25519Signature{ }

/// Minimal example:
/// ```
/// use libcrux_primitive_api::signature::*;
/// 
/// let (sk, vk) = DefaultSigningKey::keygen().expect("Keygen failed");
/// 
/// let msg = b"Test message";
/// let sig = sk.sign(msg).expect("Signing failed");
/// 
/// match vk.verify(msg, sig) {
///     Ok(_) => println!("Valid signature"),
///     Err(Error::InvalidSignature) => println!("Invalid signature"),
///     Err(Error::Verify) => println!("Verification had an internal error"),
///     _ => println!("Unexpected Error"),
/// }
/// ```
/// 
/// Specific type example:
/// ```
/// use libcrux_primitive_api::signature::*;
/// 
/// let (sk, vk) = libcrux_ed25519::SigningKey::keygen().expect("Keygen failed");
/// 
/// let msg = b"Test message";
/// let sig = sk.sign(msg).expect("Signing failed");
/// 
/// match vk.verify(msg, sig) {
///     Ok(_) => println!("Valid signature"),
///     Err(Error::InvalidSignature) => println!("Invalid signature"),
///     Err(Error::Verify) => println!("Verification had an internal error"),
///     _ => println!("Unexpected Error"),
/// }
/// ```
/// Missing: signing key from file
/// Missing: Verification for existing signature
/// 
/// Marker traits: implement markers to specify security notions, robustness properties...
/// 
/// To document (via Marker traits):
/// Minimum bits of security
/// Security notions like EUF SUF
/// 
/// Length requirements for variable length input/output schemes
/// 
/// In future: Default is PQ
pub trait SigningKey<const N: usize>: Send + Sync + Sized + for<'a> TryFrom<PrivatePkcs8KeyDer<'a>>{
    type PublicKey: VerificationKey + NetworkObject;
    type Signature: NetworkObject;

    fn keygen() -> Result<(Self, Self::PublicKey), Error> {
        todo!()
    }

    // A signing key can sign given a message, extra parameters and a randomness source
    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error>;

    // Get the public key belonging to this Signing Key
    fn to_public(&self) -> &Self::PublicKey;

    fn scheme(&self) -> SignatureScheme;
}

// A public key to verify a signature
pub trait VerificationKey: NetworkObject{
    type Signature: NetworkObject;
    const SCHEME: SignatureScheme;

    // Check if the signature is valid for the given payload and key
    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Error>;

    fn scheme(&self) -> SignatureScheme{
        Self::SCHEME
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SignatureScheme {
    EcDsaP256(DigestAlgorithm),
    Ed25519,
}

const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

#[derive(Clone, Debug)]
pub struct SigningKeyID<Scheme: Sig, Vk: VerificationKey> {
    id: ID,
    public_key: Vk,
    marker: PhantomData<Scheme>,
}

impl SigningKeyID<EcDsaP256, EcDsaP256PublicKey::<SHA256>> {
    pub fn new(id: ID, public_key: EcDsaP256PublicKey::<SHA256>) -> Self {
        Self {
            id,
            public_key,
            marker: PhantomData,
        }
    }
}

impl SigningKeyID<Ed25519, Ed25519PublicKey> {
    pub fn new(id: ID, public_key: Ed25519PublicKey) -> Self {
        Self {
            id,
            public_key,
            marker: PhantomData,
        }
    }
}

impl SigningKey<64> for SigningKeyID<Ed25519, Ed25519PublicKey> {
    type PublicKey = Ed25519PublicKey;
    type Signature = signatures::Ed25519Signature;

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        let agent = get_agent().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        agent
            .ed25519_sign_for_id(self.id.clone(), payload)
            .map_err(|_| Error::InternalError("Agent signing failed".into()))
    }

    fn to_public(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

impl TryFrom<PrivatePkcs8KeyDer<'_>> for SigningKeyID<Ed25519, Ed25519PublicKey> {
    type Error = pkcs8::Error;

    fn try_from(der: PrivatePkcs8KeyDer<'_>) -> Result<Self, Self::Error> {
        type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;

        let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
        let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

        match algo_oid_arcs.as_slice() {
            // `id-Ed25519' from RFC rfc8410
            [1, 3, 101, 112] => {
                let public_key = private_key_info.public_key.ok_or(pkcs8::Error::KeyMalformed)?;
                let public_key: [u8; 32] = public_key.as_bytes().ok_or(pkcs8::Error::KeyMalformed)?.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?;
                let public_key = Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(public_key));

                let attrs = private_key_info.attributes.ok_or(pkcs8::Error::KeyMalformed)?;
                let id = extract_id(&attrs).ok_or(pkcs8::Error::KeyMalformed)?;

                Ok(SigningKeyID::<Ed25519, Ed25519PublicKey>::new(id, public_key))
            }
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

impl SigningKey<64> for SigningKeyID<EcDsaP256, EcDsaP256PublicKey::<SHA256>> {
    type PublicKey = EcDsaP256PublicKey::<SHA256>;
    type Signature = signatures::EcDsaP256Signature::<SHA256>;

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        let agent = get_agent().ok_or_else(|| Error::InternalError("No agent available".into()))?;
        agent
            .ecdsa_p256_sign_for_id(self.id.clone(), payload)
            .map_err(|_| Error::InternalError("Agent signing failed".into()))
    }

    fn to_public(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::EcDsaP256(DigestAlgorithm::Sha256)
    }
}

impl TryFrom<PrivatePkcs8KeyDer<'_>> for SigningKeyID<EcDsaP256, EcDsaP256PublicKey::<SHA256>> {
    type Error = pkcs8::Error;

    fn try_from(der: PrivatePkcs8KeyDer<'_>) -> Result<Self, Self::Error> {
        type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;

        let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
        let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

        match algo_oid_arcs.as_slice() {
            // `id-ecPublicKey' from RFC 3279
            [1, 2, 840, 10045, 2, 1] => {
                let parameter_oid: ObjectIdentifier = private_key_info
                    .algorithm
                    .parameters
                    .ok_or(pkcs8::Error::KeyMalformed)?
                    .to_ref()
                    .try_into().map_err(|_| pkcs8::Error::KeyMalformed)?;

                let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                // Check it is an EcDsaP256 key
                (parameter_oid_arcs.as_slice() == [1, 2, 840, 10045, 3, 1, 7]).then_some(()).ok_or(pkcs8::Error::KeyMalformed)?;

                let public_key = private_key_info.public_key.ok_or(pkcs8::Error::KeyMalformed)?;
                let public_key = public_key.as_bytes().ok_or(pkcs8::Error::KeyMalformed)?;
                let public_key = decode_ecdsa_public_key(public_key.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?)
                            .map_err(|_| pkcs8::Error::KeyMalformed)?;

                let attrs = private_key_info.attributes.ok_or(pkcs8::Error::KeyMalformed)?;
                let id = extract_id(&attrs).ok_or(pkcs8::Error::KeyMalformed)?;

                Ok(SigningKeyID::<EcDsaP256, EcDsaP256PublicKey::<SHA256>>::new(id, public_key))
            }
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

impl VerificationKey for Ed25519PublicKey {
    type Signature = libcrux_agent::signatures::Ed25519Signature;
    const SCHEME: SignatureScheme = SignatureScheme::Ed25519;

    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Error> {
        ed25519::verify(payload, &self.into_bytes(), signature.get_signature())
            .map_err(Error::from)
    }
}

impl VerificationKey for EcDsaP256PublicKey::<SHA256> {
    type Signature = libcrux_agent::signatures::EcDsaP256Signature::<SHA256>;
    const SCHEME: SignatureScheme = SignatureScheme::EcDsaP256(DigestAlgorithm::Sha256);

    fn verify(&self, payload: &[u8], signature: Self::Signature) -> Result<(), Error> {
        p256::verify(DigestAlgorithm::Sha256, payload, &signature.get_signature(), self.get_key())
            .map_err(Error::from)
    }
}

impl From<libcrux_ecdsa::Error> for Error {
    fn from(err: libcrux_ecdsa::Error) -> Self {
        match err {
            libcrux_ecdsa::Error::InvalidSignature => Error::InvalidSignature,
            _ => Error::Verify,
        }
    }
}

impl From<libcrux_ed25519::Error> for Error {
    fn from(err: libcrux_ed25519::Error) -> Self {
        match err {
            libcrux_ed25519::Error::InvalidSignature => Error::InvalidSignature,
            _ => Error::Verify,
        }
    }
}


fn extract_id(attrs: &SetOfRef<'_, Attribute>) -> Option<ID> {
    let id = attrs.get(0)?;

    let id = match id.oid {
        LOCAL_KEY_ID => id.values.get(0),
        _ => None,
    }?;

    match id.tag()  {
        OctetString::TAG => id.value().try_into().ok(),
        _ => None,
    }
}

fn decode_ecdsa_public_key(public_key: [u8; 65]) -> Result<EcDsaP256PublicKey::<SHA256>, pkcs8::Error> {
    if public_key[0] != 4u8 {
        return Err(pkcs8::Error::KeyMalformed);
    } 
    p256::PublicKey::try_from(&public_key[1..])
        .map(EcDsaP256PublicKey::<SHA256>::from)
        .map_err(|_| pkcs8::Error::KeyMalformed)
}