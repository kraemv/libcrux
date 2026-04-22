use crate::keys::*;
use crate::Error;
use libcrux_agent::kex_messages::*;
use libcrux_agent::kx::MlKem768Ciphertext;
use libcrux_agent::messages::ExportRequest;
use libcrux_agent::messages::ExportResponse;
use libcrux_agent::messages::{IPCRequest, IPCResponse, MessageKind};
use libcrux_agent::signatures::EcDsaP256SHA256;
use libcrux_agent::signatures::Ed25519;
use libcrux_agent::signing_messages::*;
use zerocopy::*;

pub(crate) fn handle_request(request: &IPCRequest) -> Result<IPCResponse, Error> {
    match request.get_type().get_type() {
        MessageKind::EcDsaP256Sign => {
            let request = SignRequest::<EcDsaP256SHA256>::try_from(request.get_payload())?;
            handle_ecdsa_p256_sign_request(&request)
        }
        MessageKind::Ed25519Sign => {
            let request = SignRequest::<Ed25519>::try_from(request.get_payload())?;
            handle_ed25519_sign_request(&request)
        }

        MessageKind::MlKem768Decaps => {
            let request = MlKem768DecapsRequest::try_ref_from_bytes(request.get_payload())
                .map_err(|_| Error::MalformedRequest)?;
            handle_mlkem768_decaps(request)
        }

        MessageKind::MlKem768Encaps => {
            let request = MlKem768EncapsRequest::try_ref_from_bytes(request.get_payload())
                .map_err(|_| Error::MalformedRequest)?;
            handle_mlkem768_encaps(request)
        }

        MessageKind::MlKem768KeyGen => handle_mlkem768_key_gen(),

        MessageKind::X25519Derive => {
            let request = X25519DeriveRequest::try_ref_from_bytes(request.get_payload())
                .map_err(|_| Error::MalformedRequest)?;
            handle_x25519_derive(request)
        }

        MessageKind::X25519KeyGen => handle_x25519_key_gen(),

        MessageKind::Export => {
            let request = ExportRequest::try_ref_from_bytes(request.get_payload())
                .map_err(|_| Error::MalformedRequest)?;
            let response = ExportResponse::new(export_key(request.get_id())?);
            Ok(IPCResponse::from(response))
        }
    }
}

pub(crate) fn handle_ecdsa_p256_sign_request(
    request: &SignRequest<EcDsaP256SHA256>,
) -> Result<IPCResponse, Error> {
    ecdsa_p256_sign_for_id(*request.get_id(), request.get_payload())
        .map(|sig| IPCResponse::from(SignResponse::<EcDsaP256SHA256>::from(sig)))
}

pub(crate) fn handle_ed25519_sign_request(
    request: &SignRequest<Ed25519>,
) -> Result<IPCResponse, Error> {
    ed25519_sign_for_id(*request.get_id(), request.get_payload())
        .map(|sig| IPCResponse::from(SignResponse::<Ed25519>::from(sig)))
}

pub(crate) fn handle_x25519_key_gen() -> Result<IPCResponse, Error> {
    x25519_generate_key_id().map(|(id, pk)| IPCResponse::from(X25519KeyGenResponse::new(id, pk)))
}

pub(crate) fn handle_mlkem768_key_gen() -> Result<IPCResponse, Error> {
    mlkem_768_generate_key_id()
        .map(|(id, pk)| IPCResponse::from(MlKem768KeyGenResponse::new(id, pk)))
}

pub(crate) fn handle_x25519_derive(request: &X25519DeriveRequest) -> Result<IPCResponse, Error> {
    x25519_derive_for_key_id(*request.get_id(), request.get_key())
        .map(|shk| IPCResponse::from(X25519DeriveResponse::new(shk)))
}

pub(crate) fn handle_mlkem768_decaps(
    request: &MlKem768DecapsRequest,
) -> Result<IPCResponse, Error> {
    let ct =
        libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(request.get_ciphertext().as_bytes());
    mlkem_768_decaps_for_id(*request.get_id(), ct)
        .map(|shk| IPCResponse::from(MlKem768DecapsResponse::new(shk)))
}

pub(crate) fn handle_mlkem768_encaps(
    request: &MlKem768EncapsRequest,
) -> Result<IPCResponse, Error> {
    let pk = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(request.get_key().as_bytes());
    mlkem_768_encaps_for_id(&pk).map(|(id, ct)| {
        IPCResponse::from(MlKem768EncapsResponse::new(
            id,
            MlKem768Ciphertext::new(*ct.as_slice()),
        ))
    })
}
