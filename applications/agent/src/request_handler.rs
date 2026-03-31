use libcrux_agent::messages::*;
use crate::keys::{sign_for_ecdsa_p256_id, sign_for_ed25519_id};
use crate::Error;

pub(crate) fn handle_request(request: &IPCRequest) -> Result<IPCResponse, Error> {
    match request.get_type().get_type() {
        MessageKind::EcDsaP256Sign => {
            let request = EcDsaP256SignRequest::try_from(request.get_payload())?;
            handle_ecdsa_p256_sign_request(&request)
        }
        MessageKind::Ed25519Sign => {
            let request = Ed25519SignRequest::try_from(request.get_payload())?;
            handle_ed25519_sign_request(&request)
        }
    }
}

pub(crate) fn handle_ecdsa_p256_sign_request(request: &EcDsaP256SignRequest) -> Result<IPCResponse, Error> {
    sign_for_ecdsa_p256_id(*request.get_id(), request.get_payload())
        .map(|sig| IPCResponse::from(EcDsaP256SignResponse::from(sig)))

}

pub(crate) fn handle_ed25519_sign_request(request: &Ed25519SignRequest) -> Result<IPCResponse, Error> {
    sign_for_ed25519_id(*request.get_id(), request.get_payload())
        .map(|sig| IPCResponse::from(Ed25519SignResponse::from(sig)))

}