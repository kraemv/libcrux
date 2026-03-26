use crate::Error;
use crate::messages::*;
use crate::signatures::{EcDsaP256PrivateKey, EcDsaP256PublicKey, EcDsaP256Signature, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

use ipc_channel::ipc::*;
use zerocopy::TryFromBytes;

use std::process::{Child, Command};

pub struct Agent {
    tx: IpcBytesSender,
    rx: IpcBytesReceiver,
    proc: Child,
}

impl Agent {
    pub fn connect_agent() -> Result<Self, Error> {
        let (server, name) = IpcOneShotServer::<(IpcBytesSender, IpcBytesReceiver)>::new().map_err(|_| Error::IO)?;
        
        let proc = Command::new("agent")
            .arg(name)
            .spawn()
            .expect("failed to start bash");

        // Wait until the child is ready
        let (tx, rx) = server.accept().unwrap().1;
        
        Ok(Self { tx, rx, proc })
    }

    pub fn init_agent(&self) -> Result<(), Error> {
        let init_request = IPCSetupRequest::init_request();
        self.tx.send(&init_request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;
        match response.get_header().get_type() {
            SetupMessageKind::AgentInit => {
                match InitResult::try_ref_from_bytes(response.get_payload()) {
                    Ok(InitResult::Success(_)) => Ok(()),
                    Ok(InitResult::Failure(e)) => Err(e.clone()),
                    Err(_) => Err(Error::IO),
                }
            }
            _ => Err(Error::MalformedResponse)
        }
    }

    pub fn add_ecdsa_p256_key(&self, key: EcDsaP256PrivateKey) -> Result<([u8; 32], EcDsaP256PublicKey), Error> {
        let setup_request = EcDsaP256SetupRequest::from(&key);
        let request = IPCSetupRequest::from(setup_request);
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;
        match response.get_header().get_type() {
            SetupMessageKind::EcDsaP256Key => {
                let response = EcDsaP256SetupResponse::try_ref_from_bytes(response.get_payload()).map_err(|_| Error::MalformedResponse)?;
                let pk = EcDsaP256PublicKey::from(response);
                Ok((*response.get_id(), pk))
            }
            _ => Err(Error::MalformedResponse)
        }
    }

    pub fn add_ed25519_key(&self, key: Ed25519PrivateKey) -> Result<([u8; 32], Ed25519PublicKey), Error> {
        let setup_request = Ed25519SetupRequest::from(&key);
        let request = IPCSetupRequest::from(setup_request);
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCSetupResponse::try_from(response.as_slice())?;
        match response.get_header().get_type() {
            SetupMessageKind::Ed25519Key => {
                let response = Ed25519SetupResponse::try_ref_from_bytes(response.get_payload()).map_err(|_| Error::MalformedResponse)?;
                let pk = Ed25519PublicKey::from(response);
                Ok((*response.get_id(), pk))
            }
            _ => Err(Error::MalformedResponse)
        }
    }

    pub fn sign_for_ecdsa_p256_id(&self, id: [u8; 32], message: Vec<u8>) -> Result<EcDsaP256Signature, Error> {
        let sign_request = EcDsaP256SignRequest::new(id, message);
        let request = IPCRequest::from(sign_request);
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCResponse::try_from(response.as_ref())?;
        match response.get_header().get_type() {
            MessageKind::EcDsaP256Sign => {
                let response = EcDsaP256SignResponse::try_ref_from_bytes(response.get_payload()).map_err(|_| Error::MalformedResponse)?;
                Ok(EcDsaP256Signature::from(response))
            }
            _ => Err(Error::MalformedResponse)
        }
    }

    pub fn sign_for_ed25519_id(&self, id: [u8; 32], message: Vec<u8>) -> Result<Ed25519Signature, Error> {
        let sign_request = Ed25519SignRequest::new(id, message);
        let request = IPCRequest::from(sign_request);
        self.tx.send(&request.into_bytes()).map_err(|_| Error::IO)?;

        let response = self.rx.recv().map_err(|_| Error::IO)?;
        let response = IPCResponse::try_from(response.as_ref())?;
        match response.get_header().get_type() {
            MessageKind::Ed25519Sign => {
                let response = Ed25519SignResponse::try_ref_from_bytes(response.get_payload()).map_err(|_| Error::MalformedResponse)?;
                Ok(Ed25519Signature::from(response))
            }
            _ => Err(Error::MalformedResponse)
        }   
    }
}