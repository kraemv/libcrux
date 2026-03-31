use crate::{Error, signatures::{EcDsaP256PrivateKey, EcDsaP256PublicKey, EcDsaP256Signature, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature}};

use libcrux_ecdsa as ecdsa;
use libcrux_ed25519 as ed25519;
use libcrux_sha2::Algorithm;
use zerocopy::*;

#[derive(Clone, Copy, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
enum DigestAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

pub struct EcDsaP256SignRequest {
    id: [u8; 32],
    message: Vec<u8>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct EcDsaP256SignResponse {
    algorithm: DigestAlgorithm,
    signature: [u8; 64],
}

pub struct Ed25519SignRequest {
    id: [u8; 32],
    message: Vec<u8>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Ed25519SignResponse {
    signature: [u8; 64],
}


#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum MessageKind {
    EcDsaP256Sign,
    Ed25519Sign,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum SetupMessageKind {
    AgentInit,
    EcDsaP256Key,
    Ed25519Key,
}


#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[repr(Rust, packed)]
pub struct IPCMessageHeader {
    kind: MessageKind,
    response_len: u32,
}

pub struct IPCRequest {
    header: IPCMessageHeader,
    payload: Vec<u8>,
}

pub struct IPCResponse {
    header: IPCMessageHeader,
    payload: Vec<u8>,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum InitResult {
    Success(u8),
    Failure(Error),
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct EcDsaP256SetupRequest {
    alg: DigestAlgorithm,
    sk: [u8; 32],
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Ed25519SetupRequest {
    sk: [u8; 32],
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct EcDsaP256SetupResponse {
    alg: DigestAlgorithm,
    id: [u8; 32],
    pk: [u8; 64],
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Ed25519SetupResponse {
    id: [u8; 32],
    pk: [u8; 32],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(Rust, packed)]
pub struct IPCSetupMessageHeader {
    kind: SetupMessageKind,
    response_len: u32,
}

pub struct IPCSetupRequest {
    header: IPCSetupMessageHeader,
    payload: Vec<u8>,
}

pub struct IPCSetupResponse {
    header: IPCSetupMessageHeader,
    payload: Vec<u8>,
}

impl From<Algorithm> for DigestAlgorithm {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::Sha224 => DigestAlgorithm::Sha224,
            Algorithm::Sha256 => DigestAlgorithm::Sha256,
            Algorithm::Sha384 => DigestAlgorithm::Sha384,
            Algorithm::Sha512 => DigestAlgorithm::Sha512,
        }
    }
}

impl From<DigestAlgorithm> for Algorithm {
    fn from(alg: DigestAlgorithm) -> Self {
        match alg {
            DigestAlgorithm::Sha224 => Algorithm::Sha224,
            DigestAlgorithm::Sha256 => Algorithm::Sha256,
            DigestAlgorithm::Sha384 => Algorithm::Sha384,
            DigestAlgorithm::Sha512 => Algorithm::Sha512,
        }
    }
}

impl EcDsaP256SignRequest {
    pub fn new(id: [u8; 32], message: Vec<u8>) -> Self {
        Self { id, message }
    }

    pub fn get_id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.message
    }
}

impl TryFrom<&[u8]> for EcDsaP256SignRequest {
    type Error = Error;

    fn try_from(request: &[u8]) -> Result<Self, Self::Error> {
        let (id, message) = request.split_at_checked(32).ok_or(Error::MalformedRequest)?;
        let id: [u8; 32] = id.try_into().expect("No panic here!");
        Ok(Self { id, message: message.to_vec() })
    }
}

impl From<EcDsaP256SignRequest> for Vec<u8> {
    fn from(request: EcDsaP256SignRequest) -> Self {
        let mut result = request.id.to_vec();
        result.extend(request.message);
        result
    }
}

impl From<EcDsaP256Signature> for EcDsaP256SignResponse {
    fn from(sig: EcDsaP256Signature) -> Self {
        let mut signature = [0u8; 64];
        let signature_components = sig.get_signature();
        let (r, s) = signature_components.as_bytes();
        signature[..32].copy_from_slice(r);
        signature[32..].copy_from_slice(s);
        
        Self { algorithm: sig.get_alg().into(), signature}
    }
}

impl From<&EcDsaP256SignResponse> for EcDsaP256Signature {
    fn from(sig: &EcDsaP256SignResponse) -> Self {
        let alg = sig.algorithm;
        let signature = ecdsa::p256::Signature::from_bytes(sig.signature);

        EcDsaP256Signature::new(signature, alg.into())
    }
}

impl Ed25519SignRequest {
    pub fn new(id: [u8; 32], message: Vec<u8>) -> Self {
        Self { id, message }
    }

    pub fn get_id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.message
    }
}

impl TryFrom<&[u8]> for Ed25519SignRequest {
    type Error = Error;

    fn try_from(request: &[u8]) -> Result<Self, Self::Error> {
        let (id, message) = request.split_at_checked(32).ok_or(Error::MalformedRequest)?;
        let id: [u8; 32] = id.try_into().expect("No panic here!");
        Ok(Self { id, message: message.to_vec() })
    }
}

impl From<Ed25519SignRequest> for Vec<u8> {
    fn from(request: Ed25519SignRequest) -> Self {
        let mut result = request.id.to_vec();
        result.extend(request.message);
        result
    }
}

impl From<Ed25519Signature> for Ed25519SignResponse {
    fn from(sig: Ed25519Signature) -> Self {
        Self { signature: sig.into_bytes() }        
    }
}

impl From<&Ed25519SignResponse> for Ed25519Signature {
    fn from(sig: &Ed25519SignResponse) -> Self {
        let signature = ed25519::Signature::from_bytes(sig.signature);

        Ed25519Signature::new(signature)
    }
}

impl IPCRequest {
    pub fn get_type(&self) -> &IPCMessageHeader {
        &self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend(self.payload);

        buffer
    }
}

impl From<EcDsaP256SignRequest> for IPCRequest {
    fn from(request: EcDsaP256SignRequest) -> Self {
        let payload = Vec::<u8>::from(request);
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader{kind: MessageKind::EcDsaP256Sign, response_len};
        Self { header, payload }
    }
}

impl From<Ed25519SignRequest> for IPCRequest {
    fn from(request: Ed25519SignRequest) -> Self {
        let payload = Vec::<u8>::from(request);
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader{kind: MessageKind::Ed25519Sign, response_len};
        Self { header, payload }
    }
}

impl TryFrom<&[u8]> for IPCRequest {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, payload) = IPCMessageHeader::try_read_from_prefix(value).map_err(|_| Error::MalformedRequest)?;
        let payload_len = header.get_len() as usize;
        let payload = payload.split_at_checked(payload_len).ok_or(Error::MalformedRequest)?.0.to_vec();
        Ok(Self { header, payload })
    }
}

impl IPCSetupRequest {
    pub fn init_request() -> Self {
        let header = IPCSetupMessageHeader::new(SetupMessageKind::AgentInit, 0);
        Self { header, payload: Vec::new() }
    }

    pub fn get_type(&self) -> &IPCSetupMessageHeader {
        &self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend(self.payload);

        buffer
    }
}

impl From<EcDsaP256SetupRequest> for IPCSetupRequest {
    fn from(request: EcDsaP256SetupRequest) -> Self {
        let payload = request.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCSetupMessageHeader{kind: SetupMessageKind::EcDsaP256Key, response_len};
        Self { header, payload }
    }
}

impl From<Ed25519SetupRequest> for IPCSetupRequest {
    fn from(request: Ed25519SetupRequest) -> Self {
        let payload = request.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCSetupMessageHeader{kind: SetupMessageKind::Ed25519Key, response_len};
        Self { header, payload }
    }
}

impl TryFrom<&[u8]> for IPCSetupRequest {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, payload) = IPCSetupMessageHeader::try_read_from_prefix(value).map_err(|_| Error::MalformedRequest)?;
        let payload_len = header.get_len() as usize;
        let payload = payload.split_at_checked(payload_len).ok_or(Error::MalformedRequest)?.0.to_vec();
        Ok(Self { header, payload })
    }
}

impl IPCResponse {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend(self.payload);

        buffer
    }

    pub fn get_header(&self) -> &IPCMessageHeader {
        &self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TryFrom<&[u8]> for IPCResponse {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, payload) = IPCMessageHeader::try_read_from_prefix(value).map_err(|_| Error::MalformedRequest)?;
        let payload_len = header.get_len() as usize;
        let payload = payload.split_at_checked(payload_len).ok_or(Error::MalformedRequest)?.0.to_vec();
        Ok(Self { header, payload })
    }
}

impl From<EcDsaP256SignResponse> for IPCResponse {
    fn from(value: EcDsaP256SignResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload.len().try_into().expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::EcDsaP256Sign, payload_len);
        Self { header, payload }
    }
}

impl From<Ed25519SignResponse> for IPCResponse {
    fn from(value: Ed25519SignResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload.len().try_into().expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::Ed25519Sign, payload_len);
        Self { header, payload }
    }
}

impl IPCSetupResponse {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend(self.payload);

        buffer
    }

    pub fn get_header(&self) -> &IPCSetupMessageHeader {
        &self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TryFrom<&[u8]> for IPCSetupResponse {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, payload) = IPCSetupMessageHeader::try_read_from_prefix(value).map_err(|_| Error::MalformedRequest)?;
        let payload_len = header.get_len() as usize;
        let payload = payload.split_at_checked(payload_len).ok_or(Error::MalformedRequest)?.0.to_vec();
        Ok(Self { header, payload })
    }
}

impl IPCMessageHeader {
    pub(crate) fn new(kind: MessageKind, response_len: u32) -> Self {
        Self { kind, response_len }
    }

    pub fn get_type(&self) -> &MessageKind {
        &self.kind
    }

    pub fn get_len(&self) -> u32 {
        self.response_len
    }
}

impl IPCSetupMessageHeader {
    pub fn new(kind: SetupMessageKind, response_len: u32) -> Self {
        Self { kind, response_len }
    }

    pub fn get_type(&self) -> &SetupMessageKind {
        &self.kind
    }

    pub fn get_len(&self) -> u32 {
        self.response_len
    }
}

impl EcDsaP256SetupResponse {
    pub fn new(id: [u8; 32], pk: EcDsaP256PublicKey) -> Self {
        Self { alg: pk.get_alg().into(), pk: pk.get_key().0, id }
    }

    pub fn get_id(&self) -> &[u8; 32] {
        &self.id
    }
}

impl From<&EcDsaP256SetupResponse> for EcDsaP256PublicKey {
    fn from(response: &EcDsaP256SetupResponse) -> Self {
        EcDsaP256PublicKey::new(ecdsa::p256::PublicKey(response.pk), response.alg.into())
    }
}

impl Ed25519SetupResponse {
    pub fn new(id: [u8; 32], pk: Ed25519PublicKey) -> Self {
        Self { id, pk: pk.into_bytes() }
    }

    pub fn get_id(&self) -> &[u8; 32] {
        &self.id
    }
}

impl From<&Ed25519SetupResponse> for Ed25519PublicKey {
    fn from(response: &Ed25519SetupResponse) -> Self {
        Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(*response.get_id()))
    }
}

impl TryFrom<&EcDsaP256SetupRequest> for EcDsaP256PrivateKey {
    type Error = Error;

    fn try_from(request: &EcDsaP256SetupRequest) -> Result<Self, Error> {
        let sk = libcrux_ecdsa::p256::PrivateKey::try_from(&request.sk).map_err(|_| Error::MalformedRequest)?;
        Ok(EcDsaP256PrivateKey::new(sk, request.alg.into()))
    }
}

impl From<&EcDsaP256PrivateKey> for EcDsaP256SetupRequest {
    fn from(key: &EcDsaP256PrivateKey) -> Self {
        Self { alg: key.get_alg().into(), sk: *key.as_bytes() }
    }
}

impl From<&Ed25519SetupRequest> for Ed25519PrivateKey {
    fn from(request: &Ed25519SetupRequest) -> Self {
        let sk = libcrux_ed25519::SigningKey::from_bytes(request.sk);
        Ed25519PrivateKey::new(sk)
    }
}

impl From<&Ed25519PrivateKey> for Ed25519SetupRequest {
    fn from(key: &Ed25519PrivateKey) -> Self {
        Self { sk: *key.as_bytes() }
    }
}

impl From<Result<(), Error>> for InitResult {
    fn from(res: Result<(), Error>) -> Self {
        match res {
            Ok(()) => InitResult::Success(1),
            Err(e) => InitResult::Failure(e)
        }
    }
}

impl From<&EcDsaP256SetupResponse> for IPCSetupResponse {
    fn from(res: &EcDsaP256SetupResponse) -> Self {
        let payload = res.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCSetupMessageHeader { kind: SetupMessageKind::EcDsaP256Key, response_len};
        Self { header , payload }
    }
}

impl From<&Ed25519SetupResponse> for IPCSetupResponse {
    fn from(res: &Ed25519SetupResponse) -> Self {
        let payload = res.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCSetupMessageHeader { kind: SetupMessageKind::Ed25519Key, response_len};
        Self { header , payload }
    }
}

impl From<&InitResult> for IPCSetupResponse {
    fn from(res: &InitResult) -> Self {
        let payload = res.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCSetupMessageHeader { kind: SetupMessageKind::AgentInit, response_len};
        Self { header , payload }
    }
}