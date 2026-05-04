use crate::hkdf_messages::*;
use crate::ipc::IpcMessage;
use crate::kex_messages::*;
use crate::signatures::{EcDsaP256PublicKey, EcDsaP256SHA256, Ed25519, Ed25519PublicKey, SHA256};
use crate::signing_messages::*;
use crate::ID;
use zerocopy::*;

// ---------------------------------------------------------------------------
// Message-kind enumerations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum MessageKind {
    EcDsaP256Sign,
    Ed25519Sign,
    Export,
    HkdfExtractPublic,
    HkdfExtractSecret,
    HkdfExpand,
    MlKem768KeyGen,
    MlKem768Decaps,
    MlKem768Encaps,
    X25519KeyGen,
    X25519Derive,
}

#[derive(Clone, Copy, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum SetupMessageKind {
    AgentInit,
    EcDsaP256Key,
    Ed25519Key,
}

// ---------------------------------------------------------------------------
// Type aliases — callers continue to use these familiar names
// ---------------------------------------------------------------------------

pub type IPCRequest = IpcMessage<MessageKind>;
pub type IPCResponse = IpcMessage<MessageKind>;
pub type IPCSetupRequest = IpcMessage<SetupMessageKind>;
pub type IPCSetupResponse = IpcMessage<SetupMessageKind>;

// ---------------------------------------------------------------------------
// Export request / response (defined here because they have no own module)
// ---------------------------------------------------------------------------

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct ExportRequest {
    id: ID,
}

impl ExportRequest {
    pub fn new(id: ID) -> Self {
        Self { id }
    }

    pub fn get_id(&self) -> ID {
        self.id
    }
}

pub struct ExportResponse {
    shk: Vec<u8>,
}

impl ExportResponse {
    pub fn new(shk: Vec<u8>) -> Self {
        Self { shk }
    }

    pub fn get_shk(&self) -> &[u8] {
        &self.shk
    }
}

// ---------------------------------------------------------------------------
// Constructors for zero-payload (trigger-only) messages
// ---------------------------------------------------------------------------

impl IpcMessage<MessageKind> {
    pub fn x25519_keygen() -> Self {
        Self::no_payload(MessageKind::X25519KeyGen)
    }

    pub fn mlkem768_keygen() -> Self {
        Self::no_payload(MessageKind::MlKem768KeyGen)
    }
}

impl IpcMessage<SetupMessageKind> {
    pub fn init_request() -> Self {
        Self::no_payload(SetupMessageKind::AgentInit)
    }
}

// ---------------------------------------------------------------------------
// From impls: domain types → IPC envelopes
//
// Each impl is a single call to IpcMessage::new(kind, payload); the
// serialization detail lives in the domain type itself.
// ---------------------------------------------------------------------------

impl From<ExportRequest> for IPCRequest {
    fn from(msg: ExportRequest) -> Self {
        Self::new(MessageKind::Export, msg.get_id().to_vec())
    }
}

impl From<ExportResponse> for IPCResponse {
    fn from(msg: ExportResponse) -> Self {
        Self::new(MessageKind::Export, msg.get_shk().to_vec())
    }
}

impl From<SignRequest<'_, EcDsaP256SHA256>> for IPCRequest {
    fn from(msg: SignRequest<EcDsaP256SHA256>) -> Self {
        Self::new(MessageKind::EcDsaP256Sign, Vec::<u8>::from(msg))
    }
}

impl From<SignRequest<'_, Ed25519>> for IPCRequest {
    fn from(msg: SignRequest<Ed25519>) -> Self {
        Self::new(MessageKind::Ed25519Sign, Vec::<u8>::from(msg))
    }
}

impl From<SignResponse<EcDsaP256SHA256>> for IPCResponse {
    fn from(msg: SignResponse<EcDsaP256SHA256>) -> Self {
        Self::new(MessageKind::EcDsaP256Sign, msg.as_bytes().to_vec())
    }
}

impl From<SignResponse<Ed25519>> for IPCResponse {
    fn from(msg: SignResponse<Ed25519>) -> Self {
        Self::new(MessageKind::Ed25519Sign, msg.as_bytes().to_vec())
    }
}

impl From<MlKem768KeyGenResponse> for IPCResponse {
    fn from(msg: MlKem768KeyGenResponse) -> Self {
        Self::new(MessageKind::MlKem768KeyGen, msg.as_bytes().to_vec())
    }
}

impl From<MlKem768DecapsRequest> for IPCRequest {
    fn from(msg: MlKem768DecapsRequest) -> Self {
        Self::new(MessageKind::MlKem768Decaps, msg.as_bytes().to_vec())
    }
}

impl From<MlKem768DecapsResponse> for IPCResponse {
    fn from(msg: MlKem768DecapsResponse) -> Self {
        Self::new(MessageKind::MlKem768Decaps, msg.as_bytes().to_vec())
    }
}

impl From<MlKem768EncapsRequest> for IPCRequest {
    fn from(msg: MlKem768EncapsRequest) -> Self {
        Self::new(MessageKind::MlKem768Encaps, msg.as_bytes().to_vec())
    }
}

impl From<MlKem768EncapsResponse> for IPCResponse {
    fn from(msg: MlKem768EncapsResponse) -> Self {
        Self::new(MessageKind::MlKem768Encaps, msg.as_bytes().to_vec())
    }
}

impl From<X25519KeyGenResponse> for IPCResponse {
    fn from(msg: X25519KeyGenResponse) -> Self {
        Self::new(MessageKind::X25519KeyGen, msg.as_bytes().to_vec())
    }
}

impl From<X25519DeriveRequest> for IPCRequest {
    fn from(msg: X25519DeriveRequest) -> Self {
        Self::new(MessageKind::X25519Derive, msg.as_bytes().to_vec())
    }
}

impl From<X25519DeriveResponse> for IPCResponse {
    fn from(msg: X25519DeriveResponse) -> Self {
        Self::new(MessageKind::X25519Derive, msg.as_bytes().to_vec())
    }
}

impl From<HkdfExtractRequest<ID>> for IPCRequest {
    fn from(request: HkdfExtractRequest<ID>) -> Self {
        let mut payload = request.get_header().as_bytes().to_vec();
        if let Some(id) = request.get_id() { payload.extend_from_slice(&id) }
        if let Some(salt) = request.get_salt() { payload.extend_from_slice(&salt) }
        Self::new(MessageKind::HkdfExtractSecret, payload)
    }
}

impl<'a> From<HkdfExtractRequest<&'a [u8]>> for IPCRequest {
    fn from(request: HkdfExtractRequest<&'a [u8]>) -> Self {
        let mut payload = request.get_header().as_bytes().to_vec();
        if let Some(id) = request.get_id() { payload.extend_from_slice(&id) }
        if let Some(salt) = request.get_salt() { payload.extend_from_slice(salt) }
        Self::new(MessageKind::HkdfExtractPublic, payload)
    }
}

impl From<HkdfResponse<HkdfExtractSecretSalt>> for IPCResponse {
    fn from(msg: HkdfResponse<HkdfExtractSecretSalt>) -> Self {
        Self::new(MessageKind::HkdfExtractSecret, msg.as_bytes().to_vec())
    }
}

impl From<HkdfResponse<HkdfExtractPublicSalt>> for IPCResponse {
    fn from(msg: HkdfResponse<HkdfExtractPublicSalt>) -> Self {
        Self::new(MessageKind::HkdfExtractPublic, msg.as_bytes().to_vec())
    }
}

impl From<HkdfExpandRequest<'_>> for IPCRequest {
    fn from(msg: HkdfExpandRequest<'_>) -> Self {
        Self::new(MessageKind::HkdfExpand, Vec::<u8>::from(msg))
    }
}

impl From<HkdfResponse<HkdfExpand>> for IPCResponse {
    fn from(msg: HkdfResponse<HkdfExpand>) -> Self {
        Self::new(MessageKind::HkdfExpand, msg.as_bytes().to_vec())
    }
}

// Setup channel

impl From<SetupRequest<EcDsaP256SHA256>> for IPCSetupRequest {
    fn from(msg: SetupRequest<EcDsaP256SHA256>) -> Self {
        Self::new(SetupMessageKind::EcDsaP256Key, msg.as_bytes().to_vec())
    }
}

impl From<SetupRequest<Ed25519>> for IPCSetupRequest {
    fn from(msg: SetupRequest<Ed25519>) -> Self {
        Self::new(SetupMessageKind::Ed25519Key, msg.as_bytes().to_vec())
    }
}

impl From<&SetupResponse<EcDsaP256PublicKey<SHA256>>> for IPCSetupResponse {
    fn from(msg: &SetupResponse<EcDsaP256PublicKey<SHA256>>) -> Self {
        Self::new(SetupMessageKind::EcDsaP256Key, msg.as_bytes().to_vec())
    }
}

impl From<&SetupResponse<Ed25519PublicKey>> for IPCSetupResponse {
    fn from(msg: &SetupResponse<Ed25519PublicKey>) -> Self {
        Self::new(SetupMessageKind::Ed25519Key, msg.as_bytes().to_vec())
    }
}

impl From<&InitResult> for IPCSetupResponse {
    fn from(msg: &InitResult) -> Self {
        Self::new(SetupMessageKind::AgentInit, msg.as_bytes().to_vec())
    }
}

