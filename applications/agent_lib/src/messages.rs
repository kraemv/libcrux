use crate::aead::{ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN};
use crate::aead_messages::*;
use crate::hkdf_messages::*;
use crate::hmac::{HmacSha256Mac, Sha2_256HMAC};
use crate::hmac_messages::{HmacRequest, HmacResponse};
use crate::ipc::IpcMessage;
use crate::kex_messages::*;
use crate::signatures::{EcDsaP256PublicKey, EcDsaP256SHA256, Ed25519, Ed25519PublicKey, SHA256};
use crate::signing_messages::*;
use crate::Error;
use zerocopy::*;

// ---------------------------------------------------------------------------
// Message-kind enumerations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum MessageKind {
    ChaCha20Poly1305Decrypt,
    ChaCha20Poly1305Encrypt,
    EcDsaP256Sign,
    Ed25519Sign,
    Error,
    Export,
    HkdfExtractPublic,
    HkdfExtractSecret,
    HkdfExpand,
    HmacSha2_256Authenticate,
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

impl From<ExportNonceRequest> for IPCRequest {
    fn from(msg: ExportNonceRequest) -> Self {
        Self::new(MessageKind::Export, msg.get_id().as_ref().to_vec())
    }
}

impl From<ExportNonceResponse> for IPCResponse {
    fn from(msg: ExportNonceResponse) -> Self {
        Self::new(MessageKind::Export, msg.get_shk().to_vec())
    }
}

impl From<AeadEncryptRequest<'_, ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>> for IPCRequest {
    fn from(msg: AeadEncryptRequest<'_, ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>) -> Self {
        Self::new(MessageKind::ChaCha20Poly1305Encrypt, Vec::<u8>::from(msg))
    }
}

impl From<AeadEncryptResponse<'_, ChaCha20Poly1305, CHACHA_TAG_LEN>> for IPCResponse {
    fn from(msg: AeadEncryptResponse<'_, ChaCha20Poly1305, CHACHA_TAG_LEN>) -> Self {
        Self::new(MessageKind::ChaCha20Poly1305Encrypt, msg.into())
    }
}

impl From<AeadDecryptRequest<'_, ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>> for IPCRequest {
    fn from(msg: AeadDecryptRequest<'_, ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>) -> Self {
        Self::new(MessageKind::ChaCha20Poly1305Decrypt, Vec::<u8>::from(msg))
    }
}

impl From<AeadDecryptResponse<'_, ChaCha20Poly1305>> for IPCResponse {
    fn from(msg: AeadDecryptResponse<'_, ChaCha20Poly1305>) -> Self {
        Self::new(MessageKind::ChaCha20Poly1305Decrypt, msg.into())
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

impl From<HkdfExtractSecretRequest> for IPCRequest {
    fn from(request: HkdfExtractSecretRequest) -> Self {
        let mut payload = request.get_salt().as_bytes().to_vec();
        if let Some(id) = request.get_id() { payload.extend_from_slice(id.as_ref()) }
        Self::new(MessageKind::HkdfExtractSecret, payload)
    }
}

impl<'a> From<HkdfExtractPublicRequest<'a>> for IPCRequest {
    fn from(request: HkdfExtractPublicRequest<'a>) -> Self {
        let mut payload = request.get_id().as_bytes().to_vec();
        payload.extend_from_slice(request.get_salt().as_bytes());
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

impl From<HmacRequest<'_, Sha2_256HMAC>> for IPCRequest {
    fn from(request: HmacRequest<'_, Sha2_256HMAC>) -> Self {
        Self::new(MessageKind::HmacSha2_256Authenticate, Vec::<u8>::from(request))
    }
}

impl From<HmacResponse<HmacSha256Mac>> for IPCResponse {
    fn from(msg: HmacResponse<HmacSha256Mac>) -> Self {
        Self::new(MessageKind::HmacSha2_256Authenticate, msg.as_bytes().to_vec())
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

// Errors

impl From<Error> for IPCResponse {
    fn from(msg: Error) -> Self {
        Self::new(MessageKind::Error, msg.as_bytes().to_vec())
    }
}

