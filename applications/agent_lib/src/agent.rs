use ipc_channel::ipc::{IpcBytesReceiver, IpcBytesSender, IpcOneShotServer};
use std::process::Command;
use zerocopy::TryFromBytes;

use crate::{
    kex_messages::{
        MlKem768DecapsRequest, MlKem768DecapsResponse, MlKem768EncapsRequest,
        MlKem768EncapsResponse, MlKem768KeyGenResponse, X25519DeriveRequest, X25519DeriveResponse,
        X25519KeyGenResponse,
    },
    kx::{MlKem768Ciphertext, MlKem768PublicKey, X25519PublicKey},
    messages::{ExportRequest, ExportResponse, IPCRequest, IPCResponse, MessageKind},
    signatures::{
        EcDsaP256PrivateKey, EcDsaP256PublicKey, EcDsaP256Signature, Ed25519PrivateKey,
        Ed25519PublicKey, Ed25519Signature,
    },
    signing_messages::*,
    Error, ID,
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
        if *response.get_header().get_type() == expected {
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
        key: EcDsaP256PrivateKey,
    ) -> Result<(ID, EcDsaP256PublicKey), Error> {
        let request = IPCSetupRequest::from(EcDsaP256SetupRequest::from(&key));
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;

        match response.get_header().get_type() {
            SetupMessageKind::EcDsaP256Key => {
                let r = EcDsaP256SetupResponse::try_ref_from_bytes(response.get_payload())
                    .map_err(|_| Error::MalformedResponse)?;
                Ok((*r.get_id(), EcDsaP256PublicKey::from(r)))
            }
            _ => Err(Error::MalformedResponse),
        }
    }

    pub fn ed25519_add_key(&self, key: Ed25519PrivateKey) -> Result<(ID, Ed25519PublicKey), Error> {
        let request = IPCSetupRequest::from(Ed25519SetupRequest::from(&key));
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;

        match response.get_header().get_type() {
            SetupMessageKind::Ed25519Key => {
                let r = Ed25519SetupResponse::try_ref_from_bytes(response.get_payload())
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
        message: Vec<u8>,
    ) -> Result<EcDsaP256Signature, Error> {
        let response = self.send_recv(IPCRequest::from(EcDsaP256SignRequest::new(id, message)))?;
        let payload = Self::expect_kind(&response, MessageKind::EcDsaP256Sign)?;
        let r = EcDsaP256SignResponse::try_ref_from_bytes(payload)
            .map_err(|_| Error::MalformedResponse)?;
        Ok(EcDsaP256Signature::from(r))
    }

    pub fn ed25519_sign_for_id(&self, id: ID, message: Vec<u8>) -> Result<Ed25519Signature, Error> {
        let response = self.send_recv(IPCRequest::from(Ed25519SignRequest::new(id, message)))?;
        let payload = Self::expect_kind(&response, MessageKind::Ed25519Sign)?;
        let r = Ed25519SignResponse::try_ref_from_bytes(payload)
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

    pub fn export_key(&self, id: ID) -> Result<[u8; 32], Error> {
        let response = self.send_recv(IPCRequest::from(ExportRequest::new(id)))?;
        let payload = Self::expect_kind(&response, MessageKind::Export)?;
        let r =
            ExportResponse::try_ref_from_bytes(payload).map_err(|_| Error::MalformedResponse)?;
        Ok(*r.get_shk())
    }
}
