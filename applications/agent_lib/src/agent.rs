use ipc_channel::ipc::{IpcBytesReceiver, IpcBytesSender, IpcOneShotServer};
use std::process::Command;
use zerocopy::TryFromBytes;

use crate::{
    Error, ID, kex_messages::*,
    kx::{MlKem768Ciphertext, MlKem768PublicKey, X25519PublicKey}, messages::{
        ExportRequest, ExportResponse, IPCRequest, IPCResponse, IPCSetupRequest, IPCSetupResponse,
        MessageKind, SetupMessageKind,
    }, signatures::{
        EcDsaP256PrivateKey, EcDsaP256PublicKey, EcDsaP256SHA256, EcDsaP256Signature, Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, SHA256
    },
    signing_messages::*,
    hkdf_messages::*,
};

// Type aliases for libcrux ML-KEM types to avoid repetition
type LibcruxMlKem768PublicKey = libcrux_ml_kem::mlkem768::MlKem768PublicKey;
type LibcruxMlKem768Ciphertext = libcrux_ml_kem::mlkem768::MlKem768Ciphertext;

pub struct Agent {
    tx: IpcBytesSender,
    rx: IpcBytesReceiver,
}

impl Agent {
    pub fn connect_agent(agent_path: String) -> Result<Self, Error> {
        unsafe {
            libc::umask(0o007);
        }

        std::env::set_var("TMPDIR", "/tmp/ipcdir");

        let (server, name) =
            IpcOneShotServer::<(IpcBytesSender, IpcBytesReceiver)>::new().map_err(|_| Error::IO)?;

        let mut proc = Command::new(agent_path)
            .arg(name)
            .env("TMPDIR", "/tmp/ipcdir")
            .spawn()
            .expect("failed to start agent");

        match proc.try_wait() {
            Ok(Some(_)) => Err(Error::NoAgent),
            Ok(None) => Ok(()),
            Err(_) => Err(Error::IO),
        }?;

        let (tx, rx) = server.accept().unwrap().1;
        Ok(Self { tx, rx })
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    fn send(&self, request: IPCRequest) -> Result<(), Error> {
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)
    }

    fn recv(&self) -> Result<IPCResponse, Error> {
        let bytes = self.rx.recv().map_err(|_| Error::IO)?;
        IPCResponse::try_from(bytes.as_slice())
    }

    fn send_recv(&self, request: IPCRequest) -> Result<IPCResponse, Error> {
        self.send(request)?;
        self.recv()
    }

    fn expect_kind(response: &IPCResponse, expected: MessageKind) -> Result<&[u8], Error> {
        if response.get_header().get_type() == expected {
            Ok(response.get_payload())
        } else {
            Err(Error::MalformedResponse)
        }
    }

    // -------------------------------------------------------------------------
    // Setup
    // -------------------------------------------------------------------------

    pub fn init_agent(&self) -> Result<(), Error> {
        let request = IPCSetupRequest::init_request();
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;

        match response.get_header().get_type() {
            SetupMessageKind::AgentInit => {
                match InitResult::try_ref_from_bytes(response.get_payload()) {
                    Ok(InitResult::Success) => Ok(()),
                    _ => Err(Error::IO),
                }
            }
            _ => Err(Error::MalformedResponse),
        }
    }

    pub fn ecdsa_p256_add_key(
        &self,
        key: EcDsaP256PrivateKey<SHA256>,
    ) -> Result<(ID, EcDsaP256PublicKey<SHA256>), Error> {
        let setup_request = SetupRequest::<EcDsaP256SHA256>::from(&key);
        let request = IPCSetupRequest::from(setup_request);
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;

        match response.get_header().get_type() {
            SetupMessageKind::EcDsaP256Key => {
                let r = SetupResponse::<EcDsaP256PublicKey<SHA256>>::try_from(response.get_payload())
                    .map_err(|_| Error::MalformedResponse)?;
                Ok((*r.get_id(), EcDsaP256PublicKey::<SHA256>::from(r)))
            }
            _ => Err(Error::MalformedResponse),
        }
    }

    pub fn ed25519_add_key(&self, key: Ed25519PrivateKey) -> Result<(ID, Ed25519PublicKey), Error> {
        let setup_request = SetupRequest::<Ed25519>::from(&key);
        let request = IPCSetupRequest::from(setup_request);
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;

        match response.get_header().get_type() {
            SetupMessageKind::Ed25519Key => {
                let r = SetupResponse::<Ed25519PublicKey>::try_from(response.get_payload())
                    .map_err(|_| Error::MalformedResponse)?;
                Ok((*r.get_id(), Ed25519PublicKey::from(r)))
            }
            _ => Err(Error::MalformedResponse),
        }
    }

    // -------------------------------------------------------------------------
    // Signing
    // -------------------------------------------------------------------------

    pub fn ecdsa_p256_sign_for_id(
        &self,
        id: ID,
        message: &[u8],
    ) -> Result<EcDsaP256Signature<SHA256>, Error> {
        let response = self.send_recv(IPCRequest::from(SignRequest::<EcDsaP256SHA256>::new(id, message)))?;
        let payload = Self::expect_kind(&response, MessageKind::EcDsaP256Sign)?;
        let r = SignResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(EcDsaP256Signature::from(r))
    }

    pub fn ed25519_sign_for_id(&self, id: ID, message: &[u8]) -> Result<Ed25519Signature, Error> {
        let response = self.send_recv(IPCRequest::from(SignRequest::<Ed25519>::new(id, message)))?;
        let payload = Self::expect_kind(&response, MessageKind::Ed25519Sign)?;
        let r = SignResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(Ed25519Signature::from(r))
    }

    // -------------------------------------------------------------------------
    // X25519
    // -------------------------------------------------------------------------

    pub fn x25519_generate_key_id(&self) -> Result<(ID, X25519PublicKey), Error> {
        let response = self.send_recv(IPCRequest::x25519_keygen())?;
        let payload = Self::expect_kind(&response, MessageKind::X25519KeyGen)?;
        let r = X25519KeyGenResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok((*r.get_id(), X25519PublicKey::from(r)))
    }

    pub fn x25519_derive_for_key_id(&self, id: ID, pk: X25519PublicKey) -> Result<ID, Error> {
        let response = self.send_recv(IPCRequest::from(X25519DeriveRequest::new(id, pk)))?;
        let payload = Self::expect_kind(&response, MessageKind::X25519Derive)?;
        let r = X25519DeriveResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(*r.get_id())
    }

    // -------------------------------------------------------------------------
    // ML-KEM 768
    // -------------------------------------------------------------------------

    pub fn mlkem_768_generate_key_id(&self) -> Result<(ID, LibcruxMlKem768PublicKey), Error> {
        let response = self.send_recv(IPCRequest::mlkem768_keygen())?;
        let payload = Self::expect_kind(&response, MessageKind::MlKem768KeyGen)?;
        let r = MlKem768KeyGenResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok((*r.get_id(), LibcruxMlKem768PublicKey::from(r)))
    }

    pub fn mlkem_768_decaps_for_id(
        &self,
        id: ID,
        ct: LibcruxMlKem768Ciphertext,
    ) -> Result<ID, Error> {
        let ct = MlKem768Ciphertext::new(*ct.as_slice());
        let response = self.send_recv(IPCRequest::from(MlKem768DecapsRequest::new(id, ct)))?;
        let payload = Self::expect_kind(&response, MessageKind::MlKem768Decaps)?;
        let r = MlKem768DecapsResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(*r.get_id())
    }

    pub fn mlkem_768_encaps_for_id(
        &self,
        pk: &LibcruxMlKem768PublicKey,
    ) -> Result<(ID, LibcruxMlKem768Ciphertext), Error> {
        let pk = MlKem768PublicKey::new(*pk.as_slice());
        let response = self.send_recv(IPCRequest::from(MlKem768EncapsRequest::new(pk)))?;
        let payload = Self::expect_kind(&response, MessageKind::MlKem768Encaps)?;
        let r = MlKem768EncapsResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok((
            *r.get_id(),
            LibcruxMlKem768Ciphertext::from(r.get_ct().as_bytes()),
        ))
    }

    pub fn hkdf_extract_public_salt(&self, id: Option<ID>, salt: Option<&[u8]>) -> Result<ID, Error> {
        let response = self.send_recv(IPCRequest::from(HkdfExtractRequest::new(id, salt)))?;
        let payload = Self::expect_kind(&response, MessageKind::HkdfExtractPublic)?;
        let r = HkdfResponse::<HkdfExtractPublicSalt>::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(*r.get_id())
    }

    pub fn hkdf_extract_secret_salt(&self, id: Option<ID>, salt: Option<ID>) -> Result<ID, Error> {
        let response = self.send_recv(IPCRequest::from(HkdfExtractRequest::new(id, salt)))?;
        let payload = Self::expect_kind(&response, MessageKind::HkdfExtractSecret)?;
        let r = HkdfResponse::<HkdfExtractSecretSalt>::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(*r.get_id())
    }

    pub fn hkdf_expand(&self, id: ID, output_len: usize, info: &[u8]) -> Result<ID, Error> {
        let response = self.send_recv(IPCRequest::from(HkdfExpandRequest::new(id, output_len, info)))?;
        let payload = Self::expect_kind(&response, MessageKind::HkdfExpand)?;
        let r = HkdfResponse::<HkdfExpand>::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(*r.get_id())
    }

    pub fn export_key(&self, id: ID) -> Result<Vec<u8>, Error> {
        let response = self.send_recv(IPCRequest::from(ExportRequest::new(id)))?;
        let payload = Self::expect_kind(&response, MessageKind::Export)?;
        let r =
            ExportResponse::new(payload.to_vec());
        Ok(r.get_shk().to_vec())
    }
}
